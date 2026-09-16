rule TTP_XOR_MULT_DOSStub_e44a {
  strings:
    $key_e44a = { b0 22 [2] c4 3a [2] 83 38 [2] c4 29 [2] 8a 25 [2] 86 2f [2] 91 24 [2] 8a 6a [2] b7 }

  condition:
    any of them
}