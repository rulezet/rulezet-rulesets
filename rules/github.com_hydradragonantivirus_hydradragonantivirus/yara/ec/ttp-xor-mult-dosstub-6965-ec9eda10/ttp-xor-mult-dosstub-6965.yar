rule TTP_XOR_MULT_DOSStub_6965 {
  strings:
    $key_6965 = { 3d 0d [2] 49 15 [2] 0e 17 [2] 49 06 [2] 07 0a [2] 0b 00 [2] 1c 0b [2] 07 45 [2] 3a }

  condition:
    any of them
}