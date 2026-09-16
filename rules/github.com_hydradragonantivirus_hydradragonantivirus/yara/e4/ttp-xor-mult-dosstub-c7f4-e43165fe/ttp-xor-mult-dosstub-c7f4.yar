rule TTP_XOR_MULT_DOSStub_c7f4 {
  strings:
    $key_c7f4 = { 93 9c [2] e7 84 [2] a0 86 [2] e7 97 [2] a9 9b [2] a5 91 [2] b2 9a [2] a9 d4 [2] 94 }

  condition:
    any of them
}