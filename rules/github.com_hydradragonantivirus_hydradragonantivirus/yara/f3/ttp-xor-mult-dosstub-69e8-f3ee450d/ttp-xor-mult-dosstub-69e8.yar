rule TTP_XOR_MULT_DOSStub_69e8 {
  strings:
    $key_69e8 = { 3d 80 [2] 49 98 [2] 0e 9a [2] 49 8b [2] 07 87 [2] 0b 8d [2] 1c 86 [2] 07 c8 [2] 3a }

  condition:
    any of them
}