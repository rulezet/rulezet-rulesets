rule TTP_XOR_MULT_DOSStub_f9b1 {
  strings:
    $key_f9b1 = { ad d9 [2] d9 c1 [2] 9e c3 [2] d9 d2 [2] 97 de [2] 9b d4 [2] 8c df [2] 97 91 [2] aa }

  condition:
    any of them
}