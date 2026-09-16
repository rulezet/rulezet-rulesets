rule TTP_XOR_MULT_DOSStub_6c68 {
  strings:
    $key_6c68 = { 38 00 [2] 4c 18 [2] 0b 1a [2] 4c 0b [2] 02 07 [2] 0e 0d [2] 19 06 [2] 02 48 [2] 3f }

  condition:
    any of them
}