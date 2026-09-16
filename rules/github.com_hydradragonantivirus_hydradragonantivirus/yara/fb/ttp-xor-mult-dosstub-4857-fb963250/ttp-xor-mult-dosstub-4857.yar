rule TTP_XOR_MULT_DOSStub_4857 {
  strings:
    $key_4857 = { 1c 3f [2] 68 27 [2] 2f 25 [2] 68 34 [2] 26 38 [2] 2a 32 [2] 3d 39 [2] 26 77 [2] 1b }

  condition:
    any of them
}