rule TTP_XOR_MULT_DOSStub_b730 {
  strings:
    $key_b730 = { e3 58 [2] 97 40 [2] d0 42 [2] 97 53 [2] d9 5f [2] d5 55 [2] c2 5e [2] d9 10 [2] e4 }

  condition:
    any of them
}