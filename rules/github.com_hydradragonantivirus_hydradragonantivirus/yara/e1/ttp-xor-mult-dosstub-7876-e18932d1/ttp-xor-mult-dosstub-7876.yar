rule TTP_XOR_MULT_DOSStub_7876 {
  strings:
    $key_7876 = { 2c 1e [2] 58 06 [2] 1f 04 [2] 58 15 [2] 16 19 [2] 1a 13 [2] 0d 18 [2] 16 56 [2] 2b }

  condition:
    any of them
}