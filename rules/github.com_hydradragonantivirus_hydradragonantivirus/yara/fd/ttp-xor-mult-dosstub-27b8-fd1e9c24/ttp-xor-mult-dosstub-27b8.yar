rule TTP_XOR_MULT_DOSStub_27b8 {
  strings:
    $key_27b8 = { 73 d0 [2] 07 c8 [2] 40 ca [2] 07 db [2] 49 d7 [2] 45 dd [2] 52 d6 [2] 49 98 [2] 74 }

  condition:
    any of them
}