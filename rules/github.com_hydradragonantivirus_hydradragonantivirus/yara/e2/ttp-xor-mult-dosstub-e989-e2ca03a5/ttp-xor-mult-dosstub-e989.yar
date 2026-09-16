rule TTP_XOR_MULT_DOSStub_e989 {
  strings:
    $key_e989 = { bd e1 [2] c9 f9 [2] 8e fb [2] c9 ea [2] 87 e6 [2] 8b ec [2] 9c e7 [2] 87 a9 [2] ba }

  condition:
    any of them
}