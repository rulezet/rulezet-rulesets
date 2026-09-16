rule TTP_XOR_MULT_DOSStub_f9ce {
  strings:
    $key_f9ce = { ad a6 [2] d9 be [2] 9e bc [2] d9 ad [2] 97 a1 [2] 9b ab [2] 8c a0 [2] 97 ee [2] aa }

  condition:
    any of them
}