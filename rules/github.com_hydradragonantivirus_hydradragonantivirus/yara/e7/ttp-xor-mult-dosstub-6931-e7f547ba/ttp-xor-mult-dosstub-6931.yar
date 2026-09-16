rule TTP_XOR_MULT_DOSStub_6931 {
  strings:
    $key_6931 = { 3d 59 [2] 49 41 [2] 0e 43 [2] 49 52 [2] 07 5e [2] 0b 54 [2] 1c 5f [2] 07 11 [2] 3a }

  condition:
    any of them
}