rule TTP_XOR_MULT_DOSStub_b720 {
  strings:
    $key_b720 = { e3 48 [2] 97 50 [2] d0 52 [2] 97 43 [2] d9 4f [2] d5 45 [2] c2 4e [2] d9 00 [2] e4 }

  condition:
    any of them
}