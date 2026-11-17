/* Empty host shim: firmware/spp.cpp uses only stdint/string, not Arduino APIs. */
#ifndef ARDUINO_H_SHIM
#define ARDUINO_H_SHIM
#include <stdint.h>
#include <string.h>
#endif
