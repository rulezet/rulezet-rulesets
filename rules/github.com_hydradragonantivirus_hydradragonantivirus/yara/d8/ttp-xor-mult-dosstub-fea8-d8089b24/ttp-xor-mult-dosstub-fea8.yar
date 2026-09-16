rule TTP_XOR_MULT_DOSStub_fea8 {
  strings:
    $key_fea8 = { aa c0 [2] de d8 [2] 99 da [2] de cb [2] 90 c7 [2] 9c cd [2] 8b c6 [2] 90 88 [2] ad }

  condition:
    any of them
}