rule TTP_XOR_MULT_DOSStub_e75a {
  strings:
    $key_e75a = { b3 32 [2] c7 2a [2] 80 28 [2] c7 39 [2] 89 35 [2] 85 3f [2] 92 34 [2] 89 7a [2] b4 }

  condition:
    any of them
}