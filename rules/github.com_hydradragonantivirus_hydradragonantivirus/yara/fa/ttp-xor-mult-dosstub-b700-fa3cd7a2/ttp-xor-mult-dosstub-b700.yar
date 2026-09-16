rule TTP_XOR_MULT_DOSStub_b700 {
  strings:
    $key_b700 = { e3 68 [2] 97 70 [2] d0 72 [2] 97 63 [2] d9 6f [2] d5 65 [2] c2 6e [2] d9 20 [2] e4 }

  condition:
    any of them
}