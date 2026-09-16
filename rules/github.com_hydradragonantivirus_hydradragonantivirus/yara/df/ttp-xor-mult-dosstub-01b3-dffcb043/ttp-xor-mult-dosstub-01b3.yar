rule TTP_XOR_MULT_DOSStub_01b3 {
  strings:
    $key_01b3 = { 55 db [2] 21 c3 [2] 66 c1 [2] 21 d0 [2] 6f dc [2] 63 d6 [2] 74 dd [2] 6f 93 [2] 52 }

  condition:
    any of them
}