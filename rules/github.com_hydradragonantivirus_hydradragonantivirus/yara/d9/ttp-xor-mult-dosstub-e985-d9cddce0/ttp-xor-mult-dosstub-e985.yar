rule TTP_XOR_MULT_DOSStub_e985 {
  strings:
    $key_e985 = { bd ed [2] c9 f5 [2] 8e f7 [2] c9 e6 [2] 87 ea [2] 8b e0 [2] 9c eb [2] 87 a5 [2] ba }

  condition:
    any of them
}