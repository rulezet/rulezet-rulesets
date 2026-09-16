rule TTP_XOR_MULT_DOSStub_1a76 {
  strings:
    $key_1a76 = { 4e 1e [2] 3a 06 [2] 7d 04 [2] 3a 15 [2] 74 19 [2] 78 13 [2] 6f 18 [2] 74 56 [2] 49 }

  condition:
    any of them
}