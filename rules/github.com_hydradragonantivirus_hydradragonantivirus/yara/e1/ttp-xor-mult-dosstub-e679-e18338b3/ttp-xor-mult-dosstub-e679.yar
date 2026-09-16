rule TTP_XOR_MULT_DOSStub_e679 {
  strings:
    $key_e679 = { b2 11 [2] c6 09 [2] 81 0b [2] c6 1a [2] 88 16 [2] 84 1c [2] 93 17 [2] 88 59 [2] b5 }

  condition:
    any of them
}