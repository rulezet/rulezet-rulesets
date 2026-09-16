rule TTP_XOR_MULT_DOSStub_e6e9 {
  strings:
    $key_e6e9 = { b2 81 [2] c6 99 [2] 81 9b [2] c6 8a [2] 88 86 [2] 84 8c [2] 93 87 [2] 88 c9 [2] b5 }

  condition:
    any of them
}