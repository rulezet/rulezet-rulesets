rule TTP_XOR_MULT_DOSStub_e990 {
  strings:
    $key_e990 = { bd f8 [2] c9 e0 [2] 8e e2 [2] c9 f3 [2] 87 ff [2] 8b f5 [2] 9c fe [2] 87 b0 [2] ba }

  condition:
    any of them
}