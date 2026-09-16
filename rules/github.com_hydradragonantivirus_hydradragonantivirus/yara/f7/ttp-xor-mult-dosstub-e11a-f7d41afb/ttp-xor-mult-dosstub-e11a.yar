rule TTP_XOR_MULT_DOSStub_e11a {
  strings:
    $key_e11a = { b5 72 [2] c1 6a [2] 86 68 [2] c1 79 [2] 8f 75 [2] 83 7f [2] 94 74 [2] 8f 3a [2] b2 }

  condition:
    any of them
}