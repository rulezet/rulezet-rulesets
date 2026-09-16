rule TTP_XOR_MULT_DOSStub_71b8 {
  strings:
    $key_71b8 = { 25 d0 [2] 51 c8 [2] 16 ca [2] 51 db [2] 1f d7 [2] 13 dd [2] 04 d6 [2] 1f 98 [2] 22 }

  condition:
    any of them
}