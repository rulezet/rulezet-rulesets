rule TTP_XOR_MULT_DOSStub_76b3 {
  strings:
    $key_76b3 = { 22 db [2] 56 c3 [2] 11 c1 [2] 56 d0 [2] 18 dc [2] 14 d6 [2] 03 dd [2] 18 93 [2] 25 }

  condition:
    any of them
}