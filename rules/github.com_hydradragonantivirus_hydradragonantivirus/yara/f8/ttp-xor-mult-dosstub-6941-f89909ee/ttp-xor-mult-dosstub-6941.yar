rule TTP_XOR_MULT_DOSStub_6941 {
  strings:
    $key_6941 = { 3d 29 [2] 49 31 [2] 0e 33 [2] 49 22 [2] 07 2e [2] 0b 24 [2] 1c 2f [2] 07 61 [2] 3a }

  condition:
    any of them
}