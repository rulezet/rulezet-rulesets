rule TTP_XOR_MULT_DOSStub_b7e7 {
  strings:
    $key_b7e7 = { e3 8f [2] 97 97 [2] d0 95 [2] 97 84 [2] d9 88 [2] d5 82 [2] c2 89 [2] d9 c7 [2] e4 }

  condition:
    any of them
}