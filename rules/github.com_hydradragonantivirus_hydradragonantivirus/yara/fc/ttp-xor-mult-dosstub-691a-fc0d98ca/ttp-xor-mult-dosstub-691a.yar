rule TTP_XOR_MULT_DOSStub_691a {
  strings:
    $key_691a = { 3d 72 [2] 49 6a [2] 0e 68 [2] 49 79 [2] 07 75 [2] 0b 7f [2] 1c 74 [2] 07 3a [2] 3a }

  condition:
    any of them
}