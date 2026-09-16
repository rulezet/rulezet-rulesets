rule TTP_XOR_MULT_DOSStub_38b2 {
  strings:
    $key_38b2 = { 6c da [2] 18 c2 [2] 5f c0 [2] 18 d1 [2] 56 dd [2] 5a d7 [2] 4d dc [2] 56 92 [2] 6b }

  condition:
    any of them
}