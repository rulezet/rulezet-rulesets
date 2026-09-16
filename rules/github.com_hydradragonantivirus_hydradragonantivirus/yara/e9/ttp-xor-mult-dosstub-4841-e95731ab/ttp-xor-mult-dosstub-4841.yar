rule TTP_XOR_MULT_DOSStub_4841 {
  strings:
    $key_4841 = { 1c 29 [2] 68 31 [2] 2f 33 [2] 68 22 [2] 26 2e [2] 2a 24 [2] 3d 2f [2] 26 61 [2] 1b }

  condition:
    any of them
}