rule TTP_XOR_MULT_DOSStub_71b5 {
  strings:
    $key_71b5 = { 25 dd [2] 51 c5 [2] 16 c7 [2] 51 d6 [2] 1f da [2] 13 d0 [2] 04 db [2] 1f 95 [2] 22 }

  condition:
    any of them
}