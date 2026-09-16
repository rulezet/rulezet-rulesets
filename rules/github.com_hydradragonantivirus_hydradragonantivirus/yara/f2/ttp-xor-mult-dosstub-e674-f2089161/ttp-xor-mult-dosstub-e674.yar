rule TTP_XOR_MULT_DOSStub_e674 {
  strings:
    $key_e674 = { b2 1c [2] c6 04 [2] 81 06 [2] c6 17 [2] 88 1b [2] 84 11 [2] 93 1a [2] 88 54 [2] b5 }

  condition:
    any of them
}