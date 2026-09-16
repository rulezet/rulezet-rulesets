rule TTP_XOR_MULT_DOSStub_69e5 {
  strings:
    $key_69e5 = { 3d 8d [2] 49 95 [2] 0e 97 [2] 49 86 [2] 07 8a [2] 0b 80 [2] 1c 8b [2] 07 c5 [2] 3a }

  condition:
    any of them
}