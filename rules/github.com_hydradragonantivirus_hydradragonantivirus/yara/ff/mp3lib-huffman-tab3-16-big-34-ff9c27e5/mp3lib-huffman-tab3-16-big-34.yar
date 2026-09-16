rule mp3lib_huffman_tab3__16_big_34_ {
  strings:
    $a0 = { FF F3 FF F5 FF F7 FF FB FF FD FF FF 00 22 00 02 00 12 FF FF 00 21 00 20 00 10 00 11 FF FF 00 01 00 00 }

  condition:
    $a0
}