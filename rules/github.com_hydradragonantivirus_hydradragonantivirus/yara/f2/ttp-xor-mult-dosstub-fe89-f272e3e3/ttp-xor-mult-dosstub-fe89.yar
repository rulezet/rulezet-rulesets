rule TTP_XOR_MULT_DOSStub_fe89 {
  strings:
    $key_fe89 = { aa e1 [2] de f9 [2] 99 fb [2] de ea [2] 90 e6 [2] 9c ec [2] 8b e7 [2] 90 a9 [2] ad }

  condition:
    any of them
}