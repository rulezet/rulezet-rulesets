rule TTP_XOR_MULT_DOSStub_e980 {
  strings:
    $key_e980 = { bd e8 [2] c9 f0 [2] 8e f2 [2] c9 e3 [2] 87 ef [2] 8b e5 [2] 9c ee [2] 87 a0 [2] ba }

  condition:
    any of them
}