rule TTP_XOR_MULT_DOSStub_48f0 {
  strings:
    $key_48f0 = { 1c 98 [2] 68 80 [2] 2f 82 [2] 68 93 [2] 26 9f [2] 2a 95 [2] 3d 9e [2] 26 d0 [2] 1b }

  condition:
    any of them
}