rule TTP_XOR_MULT_DOSStub_4576 {
  strings:
    $key_4576 = { 11 1e [2] 65 06 [2] 22 04 [2] 65 15 [2] 2b 19 [2] 27 13 [2] 30 18 [2] 2b 56 [2] 16 }

  condition:
    any of them
}