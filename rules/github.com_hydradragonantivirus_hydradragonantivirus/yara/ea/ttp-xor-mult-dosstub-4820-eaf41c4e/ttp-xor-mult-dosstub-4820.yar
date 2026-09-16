rule TTP_XOR_MULT_DOSStub_4820 {
  strings:
    $key_4820 = { 1c 48 [2] 68 50 [2] 2f 52 [2] 68 43 [2] 26 4f [2] 2a 45 [2] 3d 4e [2] 26 00 [2] 1b }

  condition:
    any of them
}