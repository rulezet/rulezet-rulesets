rule TTP_XOR_MULT_DOSStub_6c70 {
  strings:
    $key_6c70 = { 38 18 [2] 4c 00 [2] 0b 02 [2] 4c 13 [2] 02 1f [2] 0e 15 [2] 19 1e [2] 02 50 [2] 3f }

  condition:
    any of them
}