rule TTP_XOR_MULT_DOSStub_e61a {
  strings:
    $key_e61a = { b2 72 [2] c6 6a [2] 81 68 [2] c6 79 [2] 88 75 [2] 84 7f [2] 93 74 [2] 88 3a [2] b5 }

  condition:
    any of them
}