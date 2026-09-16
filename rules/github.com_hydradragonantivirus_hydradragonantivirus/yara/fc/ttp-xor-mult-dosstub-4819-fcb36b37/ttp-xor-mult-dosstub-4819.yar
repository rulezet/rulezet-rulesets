rule TTP_XOR_MULT_DOSStub_4819 {
  strings:
    $key_4819 = { 1c 71 [2] 68 69 [2] 2f 6b [2] 68 7a [2] 26 76 [2] 2a 7c [2] 3d 77 [2] 26 39 [2] 1b }

  condition:
    any of them
}