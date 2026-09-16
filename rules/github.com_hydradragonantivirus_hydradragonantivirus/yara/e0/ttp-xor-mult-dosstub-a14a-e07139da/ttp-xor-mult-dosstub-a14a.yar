rule TTP_XOR_MULT_DOSStub_a14a {
  strings:
    $key_a14a = { f5 22 [2] 81 3a [2] c6 38 [2] 81 29 [2] cf 25 [2] c3 2f [2] d4 24 [2] cf 6a [2] f2 }

  condition:
    any of them
}