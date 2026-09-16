rule TTP_XOR_MULT_DOSStub_03b8 {
  strings:
    $key_03b8 = { 57 d0 [2] 23 c8 [2] 64 ca [2] 23 db [2] 6d d7 [2] 61 dd [2] 76 d6 [2] 6d 98 [2] 50 }

  condition:
    any of them
}