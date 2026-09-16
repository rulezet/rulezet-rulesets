rule TTP_XOR_MULT_DOSStub_6910 {
  strings:
    $key_6910 = { 3d 78 [2] 49 60 [2] 0e 62 [2] 49 73 [2] 07 7f [2] 0b 75 [2] 1c 7e [2] 07 30 [2] 3a }

  condition:
    any of them
}