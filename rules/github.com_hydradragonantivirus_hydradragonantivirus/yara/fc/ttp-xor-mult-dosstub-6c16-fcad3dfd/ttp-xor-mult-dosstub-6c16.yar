rule TTP_XOR_MULT_DOSStub_6c16 {
  strings:
    $key_6c16 = { 38 7e [2] 4c 66 [2] 0b 64 [2] 4c 75 [2] 02 79 [2] 0e 73 [2] 19 78 [2] 02 36 [2] 3f }

  condition:
    any of them
}