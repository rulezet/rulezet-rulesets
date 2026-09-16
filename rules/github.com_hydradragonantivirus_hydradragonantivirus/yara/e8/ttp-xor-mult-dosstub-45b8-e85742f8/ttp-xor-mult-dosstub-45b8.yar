rule TTP_XOR_MULT_DOSStub_45b8 {
  strings:
    $key_45b8 = { 11 d0 [2] 65 c8 [2] 22 ca [2] 65 db [2] 2b d7 [2] 27 dd [2] 30 d6 [2] 2b 98 [2] 16 }

  condition:
    any of them
}