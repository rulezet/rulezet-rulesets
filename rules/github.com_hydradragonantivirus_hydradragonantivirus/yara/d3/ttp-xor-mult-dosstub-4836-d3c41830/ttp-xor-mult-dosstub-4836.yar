rule TTP_XOR_MULT_DOSStub_4836 {
  strings:
    $key_4836 = { 1c 5e [2] 68 46 [2] 2f 44 [2] 68 55 [2] 26 59 [2] 2a 53 [2] 3d 58 [2] 26 16 [2] 1b }

  condition:
    any of them
}