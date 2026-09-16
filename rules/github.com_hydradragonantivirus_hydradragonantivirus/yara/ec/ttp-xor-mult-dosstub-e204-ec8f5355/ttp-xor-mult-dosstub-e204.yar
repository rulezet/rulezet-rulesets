rule TTP_XOR_MULT_DOSStub_e204 {
  strings:
    $key_e204 = { b6 6c [2] c2 74 [2] 85 76 [2] c2 67 [2] 8c 6b [2] 80 61 [2] 97 6a [2] 8c 24 [2] b1 }

  condition:
    any of them
}