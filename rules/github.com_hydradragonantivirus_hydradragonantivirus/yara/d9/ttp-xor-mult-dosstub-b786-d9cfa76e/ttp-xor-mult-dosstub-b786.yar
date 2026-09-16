rule TTP_XOR_MULT_DOSStub_b786 {
  strings:
    $key_b786 = { e3 ee [2] 97 f6 [2] d0 f4 [2] 97 e5 [2] d9 e9 [2] d5 e3 [2] c2 e8 [2] d9 a6 [2] e4 }

  condition:
    any of them
}