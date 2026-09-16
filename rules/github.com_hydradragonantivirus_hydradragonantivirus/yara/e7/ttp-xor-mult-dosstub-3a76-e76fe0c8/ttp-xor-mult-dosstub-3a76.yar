rule TTP_XOR_MULT_DOSStub_3a76 {
  strings:
    $key_3a76 = { 6e 1e [2] 1a 06 [2] 5d 04 [2] 1a 15 [2] 54 19 [2] 58 13 [2] 4f 18 [2] 54 56 [2] 69 }

  condition:
    any of them
}