rule TTP_XOR_MULT_DOSStub_b7f0 {
  strings:
    $key_b7f0 = { e3 98 [2] 97 80 [2] d0 82 [2] 97 93 [2] d9 9f [2] d5 95 [2] c2 9e [2] d9 d0 [2] e4 }

  condition:
    any of them
}