rule TTP_XOR_MULT_DOSStub_4840 {
  strings:
    $key_4840 = { 1c 28 [2] 68 30 [2] 2f 32 [2] 68 23 [2] 26 2f [2] 2a 25 [2] 3d 2e [2] 26 60 [2] 1b }

  condition:
    any of them
}