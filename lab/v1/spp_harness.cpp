/* V1 harness — runs the ACTUAL firmware SPP parser (firmware/spp.cpp,
 * spp_unpack_packet) against an attacker-supplied packet, to demonstrate the
 * real over-read.  This is the one exercise that executes unmodified firmware
 * code rather than a behavioural port.
 *
 * Safety: this binary is run by the server as an isolated child process with a
 * timeout.  The deliberate out-of-bounds read / off-by-one here can only affect
 * this short-lived process, never the server or another student's session.
 *
 * A secret string is planted in memory immediately after the supplied packet.
 * The firmware parser trusts the packet's declared length and never checks that
 * the input buffer actually holds that many bytes, so a short packet with a
 * large declared length makes memcpy read past the packet into the secret,
 * copying adjacent memory into space_packet.data — an information leak.
 *
 * Build: clang++ -O0 -g -o spp_harness firmware/spp.cpp lab/v1/spp_harness.cpp \
 *          -Ilab/v1 -Ifirmware
 */
#include "spp.h"
#include <cstdio>
#include <cstring>

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: spp_harness <hexpacket>\n");
    return 2;
  }
  /* One arena: [packet bytes][planted secret][zeros].  The parser reads from
   * arena+6; a declared length larger than the packet reaches into the secret. */
  static uint8_t arena[512];
  memset(arena, 0, sizeof(arena));

  size_t n = 0;
  for (const char *p = argv[1]; p[0] && p[1] && n < 256; p += 2) {
    int hi = hexval(p[0]), lo = hexval(p[1]);
    if (hi < 0 || lo < 0) break;
    arena[n++] = (uint8_t)((hi << 4) | lo);
  }

  const char *secret = "PWNSAT{spp_overread_leaks_adjacent_memory}";
  memcpy(arena + n, secret, strlen(secret));  /* adjacent to the packet */

  space_packet_t sp;
  int ret = spp_unpack_packet(&sp, arena, (uint16_t)n);

  uint16_t declared = ((uint16_t)arena[4] << 8) | arena[5];
  printf("buffer_len=%zu\n", n);
  printf("ret=%d\n", ret);
  printf("declared_len=%u\n", declared);
  printf("copied=%u\n", (unsigned)(declared + 1));
  int dump = (int)declared + 1;
  if (dump > (int)sizeof(sp.data)) dump = (int)sizeof(sp.data);
  printf("data=");
  for (int i = 0; i < dump; i++) printf("%02x", sp.data[i]);
  printf("\n");
  return 0;
}
