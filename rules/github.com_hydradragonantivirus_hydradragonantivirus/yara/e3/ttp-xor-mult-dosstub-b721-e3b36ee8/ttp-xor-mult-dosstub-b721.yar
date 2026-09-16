rule TTP_XOR_MULT_DOSStub_b721 {
  strings:
    $key_b721 = { e3 49 [2] 97 51 [2] d0 53 [2] 97 42 [2] d9 4e [2] d5 44 [2] c2 4f [2] d9 01 [2] e4 }

  condition:
    any of them
}