rule TTP_XOR_MULT_DOSStub_6937 {
  strings:
    $key_6937 = { 3d 5f [2] 49 47 [2] 0e 45 [2] 49 54 [2] 07 58 [2] 0b 52 [2] 1c 59 [2] 07 17 [2] 3a }

  condition:
    any of them
}