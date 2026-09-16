rule TTP_XOR_MULT_DOSStub_6c27 {
  strings:
    $key_6c27 = { 38 4f [2] 4c 57 [2] 0b 55 [2] 4c 44 [2] 02 48 [2] 0e 42 [2] 19 49 [2] 02 07 [2] 3f }

  condition:
    any of them
}