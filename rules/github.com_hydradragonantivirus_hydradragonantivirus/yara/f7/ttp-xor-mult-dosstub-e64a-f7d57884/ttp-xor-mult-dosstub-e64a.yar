rule TTP_XOR_MULT_DOSStub_e64a {
  strings:
    $key_e64a = { b2 22 [2] c6 3a [2] 81 38 [2] c6 29 [2] 88 25 [2] 84 2f [2] 93 24 [2] 88 6a [2] b5 }

  condition:
    any of them
}