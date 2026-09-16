rule TTP_XOR_MULT_DOSStub_e654 {
  strings:
    $key_e654 = { b2 3c [2] c6 24 [2] 81 26 [2] c6 37 [2] 88 3b [2] 84 31 [2] 93 3a [2] 88 74 [2] b5 }

  condition:
    any of them
}