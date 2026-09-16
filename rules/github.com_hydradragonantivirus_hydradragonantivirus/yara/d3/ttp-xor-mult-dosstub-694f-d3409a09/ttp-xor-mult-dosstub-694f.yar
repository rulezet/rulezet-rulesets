rule TTP_XOR_MULT_DOSStub_694f {
  strings:
    $key_694f = { 3d 27 [2] 49 3f [2] 0e 3d [2] 49 2c [2] 07 20 [2] 0b 2a [2] 1c 21 [2] 07 6f [2] 3a }

  condition:
    any of them
}