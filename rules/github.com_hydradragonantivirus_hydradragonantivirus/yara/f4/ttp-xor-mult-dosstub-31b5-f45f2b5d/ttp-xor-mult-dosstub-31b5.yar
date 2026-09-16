rule TTP_XOR_MULT_DOSStub_31b5 {
  strings:
    $key_31b5 = { 65 dd [2] 11 c5 [2] 56 c7 [2] 11 d6 [2] 5f da [2] 53 d0 [2] 44 db [2] 5f 95 [2] 62 }

  condition:
    any of them
}