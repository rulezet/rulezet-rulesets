rule TTP_XOR_MULT_DOSStub_e669 {
  strings:
    $key_e669 = { b2 01 [2] c6 19 [2] 81 1b [2] c6 0a [2] 88 06 [2] 84 0c [2] 93 07 [2] 88 49 [2] b5 }

  condition:
    any of them
}