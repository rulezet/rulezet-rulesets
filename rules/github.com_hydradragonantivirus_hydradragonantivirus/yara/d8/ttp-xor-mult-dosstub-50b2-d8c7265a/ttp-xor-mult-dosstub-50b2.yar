rule TTP_XOR_MULT_DOSStub_50b2 {
  strings:
    $key_50b2 = { 04 da [2] 70 c2 [2] 37 c0 [2] 70 d1 [2] 3e dd [2] 32 d7 [2] 25 dc [2] 3e 92 [2] 03 }

  condition:
    any of them
}