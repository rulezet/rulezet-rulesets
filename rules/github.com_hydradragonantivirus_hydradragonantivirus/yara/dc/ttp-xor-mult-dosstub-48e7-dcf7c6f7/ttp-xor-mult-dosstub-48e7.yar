rule TTP_XOR_MULT_DOSStub_48e7 {
  strings:
    $key_48e7 = { 1c 8f [2] 68 97 [2] 2f 95 [2] 68 84 [2] 26 88 [2] 2a 82 [2] 3d 89 [2] 26 c7 [2] 1b }

  condition:
    any of them
}