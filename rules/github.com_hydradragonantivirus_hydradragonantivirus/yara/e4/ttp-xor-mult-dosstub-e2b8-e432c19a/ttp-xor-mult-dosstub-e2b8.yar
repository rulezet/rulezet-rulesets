rule TTP_XOR_MULT_DOSStub_e2b8 {
  strings:
    $key_e2b8 = { b6 d0 [2] c2 c8 [2] 85 ca [2] c2 db [2] 8c d7 [2] 80 dd [2] 97 d6 [2] 8c 98 [2] b1 }

  condition:
    any of them
}