#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nfc/nfc.h>
#include <nfc/nfc-emulation.h>
#include <errno.h>
#include <signal.h>
#include "utils/nfc-utils.h"


nfc_target nt;
nfc_context *context;
nfc_device *pnd;

#define UID_SIZE 7
#define BIN_SIZE 540
#define PASSWORD_SIZE 4

#define UID_OFFSET 468
#define PASSWORD_OFFSET 532

#define PAGE_COUNT 135

#define WRITE_COMMAND 0xa2
#define READ 		0x30
#define WRITE 		0xA2
#define SECTOR_SELECT 	0xC2
#define HALT 		0x50


uint8_t uid[UID_SIZE];
uint8_t decryptedBin[BIN_SIZE];
uint8_t encryptedBin[BIN_SIZE];
uint8_t bcc[2];
uint8_t password[PASSWORD_SIZE] = {0, 0, 0, 0};

const uint8_t dynamicLockBytes[4] = { 0x01, 0x00, 0x0f, 0xbd };
const uint8_t staticLockBytes[4] = { 0x00, 0x00, 0x0F, 0xE0 };

char* argv0;

int writePipe[2] = {-1, -1};
int readPipe[2] = {-1, -1};
int savedStdin = -1;
int savedStdout = -1;

const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

#define COMMAND_SIZE 1000

void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");
}

void writeBuffer(const char* path, uint8_t *buffer, size_t size) {
  FILE *file = fopen(path, "w");
  if (!file) {
    fprintf(stderr, "Could not open %s\n", path);
    exit(1);
  }

  if (size != fwrite(buffer, 1, size, file)) {
    fprintf(stderr, "Could not write to file\n");
    exit(1);
  }
}

void initializeNFC() {
  printf("Initializing NFC adapter\n");
  nfc_init(&context);

  if (!context) {
    printf("Unable to init libnfc (malloc)\n");
    exit(EXIT_FAILURE);
  }

  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    printf("ERROR: %s\n", "Unable to open NFC device.");
    exit(EXIT_FAILURE);
  }
  //if (nfc_initiator_init(pnd) < 0) {
  //  nfc_perror(pnd, "nfc_initiator_init");
  //  exit(EXIT_FAILURE);
  //}

  printf("NFC emulation ready\n");
}

void readFileIntoBuffer(const char *path, uint8_t *buffer, size_t size) {
  FILE *file = fopen(path, "r");
  if (!file) {
    fprintf(stderr, "Could not open %s\n", path);
    exit(1);
  }

  if (size != fread(buffer, 1, size, file)) {
    fprintf(stderr, "Read incorrect number of bytes from file: %s\n", path);
    exit(1);
  }

}

void redirectIO() {
  if (pipe(writePipe) < 0) {
    fprintf(stderr, "Could not open write pipe\n");
    exit(1);
  }

  if (pipe(readPipe) < 0) {
    fprintf(stderr, "Could not open read pipe\n");
    exit(1);
  }

  savedStdin = dup(0);
  if (dup2(writePipe[0], 0) < 0) {
    fprintf(stderr, "Could not redirect stdin\n");
    exit(1);
  }

  savedStdout = dup(1);
  if (dup2(readPipe[1], 1) < 0) {
    fprintf(stderr, "Could not redirect stdout\n");
    exit(1);
  }
}

void resetIO() {
  if (dup2(savedStdin, 0) < 0) {
    fprintf(stderr, "Could not reset stdin\n");
    exit(1);
  }

  if (dup2(savedStdout, 1) < 0) {
    fprintf(stderr, "Could not reset stdout\n");
    exit(1);
  }
}

void pipeToAmiitool(const char *args, const char* keyPath, uint8_t *inputBuffer, uint8_t *outputBuffer) {
  printf("Sending bin to amiitool...");

  redirectIO();

  int pipeSize;
  if (BIN_SIZE != (pipeSize = write(writePipe[1], inputBuffer, BIN_SIZE))) {
    fprintf(stderr, "Wrote incorrect size to pipe: %d\n", pipeSize);
    perror("write");
    exit(1);
  }

  const char *staticCommand = "./amiitool/amiitool %s -k %s";
  char command[COMMAND_SIZE + strlen(staticCommand)];

  if (strlen(keyPath) >= COMMAND_SIZE) {
    fprintf(stderr, "Key path too big\n");
    exit(1);
  }

  sprintf(command, staticCommand, args, keyPath);
  system(command);

  if (BIN_SIZE != (pipeSize = read(readPipe[0], outputBuffer, BIN_SIZE))) {
    fprintf(stderr, "Read incorrect size from pipe: %d\n", pipeSize);
    exit(1);
  }

  resetIO();

  printf("Done\n");
}

void readEncryptedBin(const char *path) {
  printf("Reading encrypted bin file\n");
  readFileIntoBuffer(path, encryptedBin, BIN_SIZE);
}

void decryptBin(const char* keyPath) {
  printf("\nDecrypting bin\n");
  pipeToAmiitool("-d", keyPath, encryptedBin, decryptedBin);
  printf("Decrypted\n");
}

void readTag() {
  printf("***Scan tag***\n");

  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0) {
    printf("Read UID: ");
    int uidSize = nt.nti.nai.szUidLen;
    print_hex(nt.nti.nai.abtUid, uidSize);

    if (UID_SIZE != uidSize) {
      fprintf(stderr, "Read wrong size UID\n");
      exit(1);
    }

    for (int i = 0; i < UID_SIZE; i++) {
      uid[i] = nt.nti.nai.abtUid[i];
    }
  }
}

void replaceUIDInBin() {
  printf("Replacing UID\n");
  bcc[0] = 0x88 ^ uid[0] ^ uid[1] ^ uid[2];
  bcc[1] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];

  int i;
  for (i = 0; i < 3; i++) {
    decryptedBin[UID_OFFSET + i] = uid[i];
  }

  decryptedBin[UID_OFFSET + i++] = bcc[0];

  for (; i < 8; i++) {
    decryptedBin[UID_OFFSET + i] = uid[i - 1];
  }
}

void replacePassword() {
  printf("Updating password\n");
  password[0] = 0xAA ^ uid[1] ^ uid[3];
  password[1] = 0x55 ^ uid[2] ^ uid[4];
  password[2] = 0xAA ^ uid[3] ^ uid[5];
  password[3] = 0x55 ^ uid[4] ^ uid[6];

  for (int i = 0; i < PASSWORD_SIZE; i++) {
    decryptedBin[PASSWORD_OFFSET + i] = password[i];
  }
}

void setDefaults() {
  printf("Writing magic bytes\n");

  decryptedBin[0] = bcc[1];

  // All of these are magic values
  decryptedBin[536] = 0x80;
  decryptedBin[537] = 0x80;

  decryptedBin[520] = 0;
  decryptedBin[521] = 0;
  decryptedBin[522] = 0;

  decryptedBin[2] = 0;
  decryptedBin[3] = 0;
}

void updateForUID() {

  printf("\nUpdating bin for new UID:\n");

  // Credit: https://gist.githubusercontent.com/ShoGinn/d27a726296f4370bbff0f9b1a7847b85/raw/aeb425e8b1708e1c61f78c3e861dad03c20ca8ab/Arduino_amiibo_tool.bash
  replaceUIDInBin();
  replacePassword();
  setDefaults();

  printf("Finished updating bin\n\n");
}

void encryptBin(const char* keyPath) {
  printf("Encrypting\n");
  pipeToAmiitool("-e", keyPath, decryptedBin, encryptedBin);
  printf("Encrypted\n\n");
}

void writePage(uint8_t page, const uint8_t *pageData) {
  printf("Writing to %d: %02x %02x %02x %02x...",
         page, pageData[0], pageData[1], pageData[2], pageData[3]);

  uint8_t sendData[6] = {
    WRITE_COMMAND, page, pageData[0], pageData[1], pageData[2], pageData[3]
  };

  int responseCode = nfc_initiator_transceive_bytes(pnd, sendData, 6, NULL, 0, 0);

  if (responseCode == 0) {
    printf("Done\n");
  } else {
    printf("Failed\n");
    fprintf(stderr, "Failed to write to tag\n");
    nfc_perror(pnd, "Write");
    exit(1);
  }
}

void writeData() {
  printf("Writing encrypted bin:\n");
  for (uint8_t i = 3; i < PAGE_COUNT; i++) {
    writePage(i, encryptedBin + (i * 4));
  }
  printf("Done\n");
}

uint8_t getData() {
  printf("Getting Data: \n");

}

void writeDynamicLockBytes() {
  printf("Writing dynamic lock bytes\n");
  writePage(130, dynamicLockBytes);
  printf("Done\n");
}

void writeStaticLockBytes() {
  printf("Writing static lock bytes\n");
  writePage(2, staticLockBytes);
  printf("Done\n");
}

void writeTag() {
  printf("Writing tag:\n");
  writeData();
  writeDynamicLockBytes();
  writeStaticLockBytes();
  printf("Finished writing tag\n");
}

nfcforum_tag2_io(struct nfc_emulator *emulator, const uint8_t *data_in, const size_t data_in_len, uint8_t *data_out, const size_t data_out_len)
{
  int res = 0;

  uint8_t *nfcforum_tag2_memory_area = (uint8_t *)(emulator->user_data);

  printf("    In: ");
  print_hex(data_in, data_in_len);

  switch (data_in[0]) {
    case READ:
      if (data_out_len >= 16) {
        memcpy(data_out, nfcforum_tag2_memory_area + (data_in[1] * 4), 16);
        res = 16;
      } else {
        res = -ENOSPC;
      }
      break;
    case HALT:
      printf("HALT sent\n");
      res = -ECONNABORTED;
      break;
    default:
      printf("Unknown command: 0x%02x\n", data_in[0]);
      res = -ENOTSUP;
  }

  if (res < 0) {
    ERR("%s (%d)", strerror(-res), -res);
  } else {
    printf("    Out: ");
    print_hex(data_out, res);
  }

  return res;
}

stop_emulation(int sig)
{
  (void)sig;
  if (pnd != NULL) {
    nfc_abort_command(pnd);
  } else {
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
}

void emulateTag() {
 printf("Emulating tag\n");
 //getData();

  nfc_target nt = {
    .nm = nmMifare,
    .nti = {
      .nai = {
        .abtAtqa = { 0x00, 0x40 },
        .abtUid = { 0x88, uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6] },
        .szUidLen = UID_SIZE,
        .btSak = 0x00,
        .szAtsLen = 0,
      }

    }
  };

  struct nfc_emulation_state_machine state_machine = {
    .io = nfcforum_tag2_io
  };

  static uint8_t firstBlocks[] = {
    0x00, 0x00, 0x00, 0x00,  // Block 0
    0x00, 0x00, 0x00, 0x00
  };

  uint32_t totalSize = sizeof(firstBlocks) + sizeof(staticLockBytes) + sizeof(encryptBin) + sizeof(dynamicLockBytes);

  uint8_t __nfcforum_tag2_memory_area[totalSize];

  strcpy(firstBlocks, __nfcforum_tag2_memory_area);
  strcat(staticLockBytes, __nfcforum_tag2_memory_area);
  strcat(encryptBin, __nfcforum_tag2_memory_area);
  strcat(dynamicLockBytes, __nfcforum_tag2_memory_area);
  //static uint8_t __nfcforum_tag2_memory_area[] = {
    //staticLockBytes,         // Block 2 (Static lock bytes: CC area and data area are read-only locked)
    //0xE1, 0x10, 0x06, 0x0F,  // Block 3 (CC - NFC-Forum Tag Type 2 version 1.0, Data area (from block 4 to the end) is 48 bytes, Read-only mode)
    //encryptBin,
    //dynamicLockBytes,
    //0x03, 33,   0xd1, 0x02,  // Block 4 (NDEF)
    //0x1c, 0x53, 0x70, 0x91,
    //0x01, 0x09, 0x54, 0x02,
    //0x65, 0x6e, 0x4c, 0x69,

    //0x62, 0x6e, 0x66, 0x63,
    //0x51, 0x01, 0x0b, 0x55,
    //0x03, 0x6c, 0x69, 0x62,
    //0x6e, 0x66, 0x63, 0x2e,

    //0x6f, 0x72, 0x67, 0x00,
    //0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00,
  //};

  struct nfc_emulator emulator = {
    .target = &nt,
    .state_machine = &state_machine,
    .user_data = __nfcforum_tag2_memory_area,
  };

  signal(SIGINT, stop_emulation);

  printf("Emulating NDEF tag now, please touch it with a second NFC device\n");


  if (nfc_emulate_target(pnd, &emulator, 0) < 0) {
    nfc_perror(pnd, argv0);
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}

void printUsage() {
  printf("pimiibo keyfile binfile\n");
}

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "Incorrect number of arguments\n");
    printUsage();
    exit(1);
  }

  argv0 = argv[0];

  readEncryptedBin(argv[2]);
  decryptBin(argv[1]);
  initializeNFC();
  readTag();
  updateForUID();
  encryptBin(argv[1]);
  //writeTag();
  emulateTag();
}


