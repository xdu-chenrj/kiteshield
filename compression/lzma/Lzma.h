#include <stdint.h>


uint8_t* lzmaCompress(const uint8_t *input, uint32_t inputSize, uint32_t *outputSize);
uint8_t* lzmaDecompress(const uint8_t *input, uint32_t inputSize, uint32_t *outputSize);
void hexdump(const uint8_t *buf, int size);