rule TTP_XOR_MULT_DOSStub_69e4 {
  strings:
    $key_69e4 = { 3d 8c [2] 49 94 [2] 0e 96 [2] 49 87 [2] 07 8b [2] 0b 81 [2] 1c 8a [2] 07 c4 [2] 3a }

  condition:
    any of them
}