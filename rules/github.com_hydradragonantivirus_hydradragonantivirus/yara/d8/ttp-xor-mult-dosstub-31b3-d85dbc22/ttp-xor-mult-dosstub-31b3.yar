rule TTP_XOR_MULT_DOSStub_31b3 {
  strings:
    $key_31b3 = { 65 db [2] 11 c3 [2] 56 c1 [2] 11 d0 [2] 5f dc [2] 53 d6 [2] 44 dd [2] 5f 93 [2] 62 }

  condition:
    any of them
}