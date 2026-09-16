rule TTP_XOR_MULT_DOSStub_f9c0 {
  strings:
    $key_f9c0 = { ad a8 [2] d9 b0 [2] 9e b2 [2] d9 a3 [2] 97 af [2] 9b a5 [2] 8c ae [2] 97 e0 [2] aa }

  condition:
    any of them
}