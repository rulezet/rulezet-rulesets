rule TTP_XOR_MULT_DOSStub_4856 {
  strings:
    $key_4856 = { 1c 3e [2] 68 26 [2] 2f 24 [2] 68 35 [2] 26 39 [2] 2a 33 [2] 3d 38 [2] 26 76 [2] 1b }

  condition:
    any of them
}