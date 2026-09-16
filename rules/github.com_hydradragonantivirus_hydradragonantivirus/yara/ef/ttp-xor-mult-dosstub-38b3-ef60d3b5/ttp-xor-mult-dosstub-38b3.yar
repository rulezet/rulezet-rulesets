rule TTP_XOR_MULT_DOSStub_38b3 {
  strings:
    $key_38b3 = { 6c db [2] 18 c3 [2] 5f c1 [2] 18 d0 [2] 56 dc [2] 5a d6 [2] 4d dd [2] 56 93 [2] 6b }

  condition:
    any of them
}