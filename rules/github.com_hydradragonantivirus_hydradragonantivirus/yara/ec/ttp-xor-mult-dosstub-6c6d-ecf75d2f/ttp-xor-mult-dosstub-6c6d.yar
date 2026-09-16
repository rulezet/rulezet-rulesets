rule TTP_XOR_MULT_DOSStub_6c6d {
  strings:
    $key_6c6d = { 38 05 [2] 4c 1d [2] 0b 1f [2] 4c 0e [2] 02 02 [2] 0e 08 [2] 19 03 [2] 02 4d [2] 3f }

  condition:
    any of them
}