//
// Created by chenrj on 23-3-5.
//

#ifndef KITESHIELD_LOADER_H
#define KITESHIELD_LOADER_H

#endif //KITESHIELD_LOADER_H

extern struct rc4_key obfuscated_key;
extern unsigned char serial_key[16];

typedef struct termios termios_t;
typedef struct serial_data {
    unsigned char data_buf[39];
    int ser_fd;
} ser_data;

void reverse_shuffle(unsigned char *arr, int n, unsigned char swap_infos[]);

void send(ser_data snd);
void receive(ser_data rec);

int common(uint8_t serial_send[SERIAL_SIZE]);

unsigned short int CRC16_Check(const unsigned char *data, unsigned char len);