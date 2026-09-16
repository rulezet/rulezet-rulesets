rule TTP_XOR_MULT_DOSStub_14b8 {
  strings:
    $key_14b8 = { 40 d0 [2] 34 c8 [2] 73 ca [2] 34 db [2] 7a d7 [2] 76 dd [2] 61 d6 [2] 7a 98 [2] 47 }

  condition:
    any of them
}