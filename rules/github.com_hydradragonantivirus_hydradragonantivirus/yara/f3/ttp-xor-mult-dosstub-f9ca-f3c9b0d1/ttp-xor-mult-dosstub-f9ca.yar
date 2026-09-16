rule TTP_XOR_MULT_DOSStub_f9ca {
  strings:
    $key_f9ca = { ad a2 [2] d9 ba [2] 9e b8 [2] d9 a9 [2] 97 a5 [2] 9b af [2] 8c a4 [2] 97 ea [2] aa }

  condition:
    any of them
}