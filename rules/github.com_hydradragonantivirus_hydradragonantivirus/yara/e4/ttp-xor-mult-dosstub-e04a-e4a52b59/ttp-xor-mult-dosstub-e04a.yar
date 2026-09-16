rule TTP_XOR_MULT_DOSStub_e04a {
  strings:
    $key_e04a = { b4 22 [2] c0 3a [2] 87 38 [2] c0 29 [2] 8e 25 [2] 82 2f [2] 95 24 [2] 8e 6a [2] b3 }

  condition:
    any of them
}