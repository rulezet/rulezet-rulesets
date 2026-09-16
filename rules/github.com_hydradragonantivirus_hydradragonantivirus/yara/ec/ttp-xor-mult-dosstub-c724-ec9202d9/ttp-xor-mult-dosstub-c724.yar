rule TTP_XOR_MULT_DOSStub_c724 {
  strings:
    $key_c724 = { 93 4c [2] e7 54 [2] a0 56 [2] e7 47 [2] a9 4b [2] a5 41 [2] b2 4a [2] a9 04 [2] 94 }

  condition:
    any of them
}