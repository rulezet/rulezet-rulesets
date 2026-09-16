rule TTP_XOR_MULT_DOSStub_e609 {
  strings:
    $key_e609 = { b2 61 [2] c6 79 [2] 81 7b [2] c6 6a [2] 88 66 [2] 84 6c [2] 93 67 [2] 88 29 [2] b5 }

  condition:
    any of them
}