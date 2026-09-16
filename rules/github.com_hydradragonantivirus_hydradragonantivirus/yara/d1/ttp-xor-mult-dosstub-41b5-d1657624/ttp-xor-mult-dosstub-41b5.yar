rule TTP_XOR_MULT_DOSStub_41b5 {
  strings:
    $key_41b5 = { 15 dd [2] 61 c5 [2] 26 c7 [2] 61 d6 [2] 2f da [2] 23 d0 [2] 34 db [2] 2f 95 [2] 12 }

  condition:
    any of them
}