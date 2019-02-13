#include <stdint.h>
#include <nfc/nfc.h>
#include "nfc-utils.h"

#define HALT_COMMAND 0x50
#define GET_VERSION_COMMAND 0x60
#define ATQA_SIZE_IN_BYTES 2
#define SAK_SIZE_IN_BYTES 1
#define ATS_FORMAT_DATA_SIZE 1
#define MAX_HISTORICAL_BYTES 14

// ATQA = Answer To Request A
// SAK = Select Acknowledge
// PCD = Proximity Coupling Device (the reader)
// PICC = Proximity Integrated Circuit Card (the NFC card / tag)

uint8_t HALT_COMMAND_BYTES[4] = { HALT_COMMAND, 0x00, 0x00, 0x00 };
const uint8_t HALT_UNLOCK_PARAMETERS[2] = { 0x40, 0x43 }; // Special parameters for "magic" cards

uint8_t GET_VERSION_COMMAND_BYTE[1] = { GET_VERSION_COMMAND };

void print_nfc_version();
void print_pcd_name(nfc_device*);
void print_atqa(nfc_iso14443a_info*);
void print_uid(nfc_iso14443a_info*);
void print_sak(nfc_iso14443a_info*);
void print_ats(nfc_iso14443a_info*);
void print_magic_type(nfc_context*, nfc_device*);
void print_card_type(nfc_iso14443a_info*, nfc_device*);
bool get_is_magic_gen1(nfc_context*, nfc_device*);
uint8_t get_historical_bytes(uint8_t*, uint8_t, uint8_t*);
char* get_card_type(nfc_iso14443a_info*, nfc_device*);
int get_target_version(nfc_device*);
void configure_pcd(nfc_context*, nfc_device*);
nfc_context* allocate_nfc_context();
nfc_device* open_pcd(nfc_context*);
nfc_target* select_picc(nfc_context*, nfc_device*);

int main(int argv, char** argc) {
	nfc_context* context = allocate_nfc_context();
	nfc_device* pcd = open_pcd(context);
	
	configure_pcd(context, pcd);

	print_nfc_version();
	print_pcd_name(pcd);

	nfc_target* target_picc = select_picc(context, pcd);
	nfc_iso14443a_info* tag_info = &(target_picc->nti.nai);

	print_atqa(tag_info);
	print_uid(tag_info);
	print_sak(tag_info);
	print_ats(tag_info);
	print_magic_type(context, pcd);
	print_card_type(tag_info, pcd);

	nfc_close(pcd);
	nfc_exit(context);

	exit(EXIT_SUCCESS);
}

nfc_context* allocate_nfc_context() {
	nfc_context* context;
	
	nfc_init(&context);

	if (context == NULL) {
		ERR("Unable to allocate memory for NFC context");

		exit(EXIT_FAILURE);
	}
}

nfc_device* open_pcd(nfc_context* context) {
	nfc_device* pcd = nfc_open(context, NULL);

	if (pcd == NULL) {
		ERR("Error opening NFC reader\n");

		nfc_exit(context);

		exit(EXIT_FAILURE);
	}
}

void configure_pcd(nfc_context* context, nfc_device* pcd) {
	int result = nfc_initiator_init(pcd);

	if (result < 0) {
		nfc_perror(pcd, "nfc_initiator_init");
		nfc_close(pcd);
		nfc_exit(context);

		exit(EXIT_FAILURE);
	}
}

nfc_target* select_picc(nfc_context* context, nfc_device* pcd) {
	const nfc_modulation mifare_modulation = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	};

	nfc_target* selected_picc;

	int picc_count = nfc_initiator_select_passive_target(pcd, mifare_modulation, NULL, 0, selected_picc);

	if (picc_count <= 0) {
		nfc_perror(pcd, "nfc_initiator_select_passive_target");
		nfc_close(pcd);
		nfc_exit(context);

		exit(EXIT_FAILURE);
	}

	return selected_picc;
}

void print_nfc_version() {
	const char* libnfc_version = nfc_version();

	printf("Using libnfc version %s\n", libnfc_version);
}

void print_pcd_name(nfc_device* pcd) {
	const char* pcd_name = nfc_device_get_name(pcd);

	printf("Using %s\n", pcd_name);
}

void print_atqa(nfc_iso14443a_info* tag_info) {
	printf("ATQA: ");
	print_hex(tag_info->abtAtqa, ATQA_SIZE_IN_BYTES);
}

void print_uid(nfc_iso14443a_info* tag_info) {
	printf("UID: ");
	print_hex(tag_info->abtUid, tag_info->szUidLen);
}

void print_sak(nfc_iso14443a_info* tag_info) {
	printf("SAK: ");
	print_hex(&tag_info->btSak, SAK_SIZE_IN_BYTES);
}

void print_ats(nfc_iso14443a_info* tag_info) {
	if (tag_info->szAtsLen) {
		printf("ATS: ");
		print_hex(tag_info->abtAts, tag_info->szAtsLen);
	}
}

void print_magic_type(nfc_context* context, nfc_device* pcd) {
	bool is_magic_gen1 = get_is_magic_gen1(context, pcd);

	if (is_magic_gen1) {
		printf("Magic card, generation 1 (manufacturer block writable with special instructions)");
	}
}

void print_card_type(nfc_iso14443a_info* tag_info, nfc_device* pcd) {
	printf("Predicted card type: ");

	char* type = get_card_type(tag_info, pcd);

	printf("%s\n", type);
}

bool get_is_magic_gen1(nfc_context* context, nfc_device* pcd) {
	if (nfc_device_set_property_bool(pcd, NP_HANDLE_CRC, false) < 0) {
		nfc_perror(pcd, "nfc_configure");

		exit(EXIT_FAILURE);
	} else if (nfc_device_set_property_bool(pcd, NP_EASY_FRAMING, false) < 0) {
		nfc_perror(pcd, "nfc_configure");

		exit(EXIT_FAILURE);
	}
	
	iso14443a_crc_append(HALT_COMMAND_BYTES, 2);

	nfc_initiator_transceive_bytes(pcd, HALT_COMMAND_BYTES, sizeof(HALT_COMMAND_BYTES), NULL, 0, -1);
	
	int first_unlock_response = nfc_initiator_transceive_bits(pcd, &HALT_UNLOCK_PARAMETERS[0], 7, NULL, NULL, 0, NULL);

	bool is_magic = false;

	if (first_unlock_response >= 0) {
		int second_unlock_response = nfc_initiator_transceive_bytes(pcd, &HALT_UNLOCK_PARAMETERS[1], sizeof(uint8_t), NULL, 0, -1);

		if (second_unlock_response >= 0) {
			is_magic = true;
		}
	}

	/*
		Setting these properties to true instead of setting them
		back to their previous values due to a seeming lack of an
		nfc_device_get_property_bool equivalent function
	*/
	if (nfc_device_set_property_bool(pcd, NP_HANDLE_CRC, true) < 0) {
		nfc_perror(pcd, "nfc_configure");

		exit(EXIT_FAILURE);
	} else if (nfc_device_set_property_bool(pcd, NP_EASY_FRAMING, true) < 0) {
		nfc_perror(pcd, "nfc_configure");

		exit(EXIT_FAILURE);
	}

	return is_magic;
}

/*
	Resources for understanding the structure of the ATS:
	http://www.emutag.com/iso/14443-4.pdf
	http://www.gorferay.com/data-transmission-protocol-iso-iec-14-433-4/ (via archive)
*/
uint8_t get_historical_bytes(uint8_t* ats, uint8_t ats_size, uint8_t* historical_bytes) {
	if (ats_size <= 1) {
		return 0;
	}

	uint8_t format_byte = ats[0];

	if ((format_byte & 0b10000000) > 0) {
		printf("Reserved bit - bit 8 of the format byte - is in use. Unable to proceed.\n");

		exit(EXIT_FAILURE);
	}

	uint8_t interface_byte_count = 0;

	if ((format_byte & 0b1000000) > 0) {
		++interface_byte_count;
	}

	if ((format_byte & 0b100000) > 0) {
		++interface_byte_count;
	}

	if ((format_byte & 0b10000)) {
		++interface_byte_count;
	}

	uint8_t historical_bytes_count = ats_size - ATS_FORMAT_DATA_SIZE - interface_byte_count;

	if (historical_bytes_count == 0) {
		return 0;
	}

	historical_bytes = malloc(historical_bytes_count);

	for (uint8_t i = 0; i < historical_bytes_count; ++i) {
		historical_bytes[i] = ats[ATS_FORMAT_DATA_SIZE + interface_byte_count + i];
	}

	return historical_bytes_count;
}

/*
	Resources for identifying card types:
	https://www.nxp.com/docs/en/application-note/AN10834.pdf
	http://nfc-tools.org/index.php/ISO14443A

	Although AN10834 describes one stage of identification of a
	DESFire as ensuring	the lack of a historical byte, a valid
	DESFire can have historical bytes. Or, at least, one: the
	"category indicator byte", as defined by ISO 7816-4.

	https://stackoverflow.com/questions/54526238/what-and-where-are-historical-bytes-in-a-mifares-ats
	http://www.embedx.com/pdfs/ISO_STD_7816/info_isoiec7816-4%7Bed21.0%7Den.pdf
*/
char* get_card_type(nfc_iso14443a_info* tag_info, nfc_device* pcd) {
	uint8_t sak = tag_info->btSak;
	uint8_t ats_size = tag_info->szAtsLen;
	uint8_t* ats = tag_info->abtAts;
	uint8_t historical_bytes[MAX_HISTORICAL_BYTES];
	uint8_t historical_bytes_size = get_historical_bytes(ats, ats_size, historical_bytes);
	
	if ((sak & 0b10) == 0) {
		if (sak & 0b1000) {
			if (sak & 0b10000) {
				if (sak & 0b1) {
					return "MIFARE Classic 2K";
				} else {
					if (sak & 0b100000) {
						return "Smart MX with MIFARE 4K";
					} else {
						if (historical_bytes_size <= 1) {
							return "MIFARE Classic 4K";
						} else {
							return "MIFARE Plus";
						}
					}
				}
			} else {
				if (sak & 0b1) {
					return "MIFARE Classic Mini";
				} else {
					if (sak & 0b100000) {
						return "Smart MX with MIFARE 1K";
					} else {
						if (historical_bytes_size <= 1) {
							return "MIFARE Classic 1K";
						} else {
							return "MIFARE Plus";
						}
					}
				}
			}
		} else {
			if (sak & 0b10000) {
				if (sak & 0b1) {
					return "MIFARE Plus X 4K card SL2";
				} else {
					return "MIFARE Plus X 2K card SL2";
				}
			} else {
				if (sak & 0b100000) {
					if (historical_bytes_size <= 1) {
						int version = get_target_version(pcd);

						if (version >= 0) {
							return "MIFARE DESFire (EV1?)";
						} else {
							return "Non-MIFARE device";
						}
					} else {
						return "MIFARE Plus";
					}
				} else {
					if (sak & 0b1) {
						return "MIFARE TagNPlay";
					} else {
						return "MIFARE Ultralight (C?)";
					}
				}
			}
		}
	} else {
		return "Unidentifiable (SAK reserved bit - bit 2 - is in use)";
	}
}

int get_target_version(nfc_device* pcd) {
	int version_response = nfc_initiator_transceive_bytes(pcd, GET_VERSION_COMMAND_BYTE, sizeof(GET_VERSION_COMMAND_BYTE), NULL, 0, -1);

	return version_response;
}
