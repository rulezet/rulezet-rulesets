rule TTP_XOR_MULT_DOSStub_71b2 {
  strings:
    $key_71b2 = { 25 da [2] 51 c2 [2] 16 c0 [2] 51 d1 [2] 1f dd [2] 13 d7 [2] 04 dc [2] 1f 92 [2] 22 }

  condition:
    any of them
}