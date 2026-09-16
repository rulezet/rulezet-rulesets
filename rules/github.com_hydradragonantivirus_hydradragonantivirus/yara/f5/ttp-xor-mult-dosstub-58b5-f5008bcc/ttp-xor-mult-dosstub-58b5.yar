rule TTP_XOR_MULT_DOSStub_58b5 {
  strings:
    $key_58b5 = { 0c dd [2] 78 c5 [2] 3f c7 [2] 78 d6 [2] 36 da [2] 3a d0 [2] 2d db [2] 36 95 [2] 0b }

  condition:
    any of them
}