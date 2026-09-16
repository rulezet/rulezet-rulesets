rule TTP_XOR_MULT_DOSStub_e254 {
  strings:
    $key_e254 = { b6 3c [2] c2 24 [2] 85 26 [2] c2 37 [2] 8c 3b [2] 80 31 [2] 97 3a [2] 8c 74 [2] b1 }

  condition:
    any of them
}