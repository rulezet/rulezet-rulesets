rule TTP_XOR_MULT_DOSStub_6972 {
  strings:
    $key_6972 = { 3d 1a [2] 49 02 [2] 0e 00 [2] 49 11 [2] 07 1d [2] 0b 17 [2] 1c 1c [2] 07 52 [2] 3a }

  condition:
    any of them
}