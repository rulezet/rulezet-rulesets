rule TTP_XOR_MULT_DOSStub_00b2 {
  strings:
    $key_00b2 = { 54 da [2] 20 c2 [2] 67 c0 [2] 20 d1 [2] 6e dd [2] 62 d7 [2] 75 dc [2] 6e 92 [2] 53 }

  condition:
    any of them
}