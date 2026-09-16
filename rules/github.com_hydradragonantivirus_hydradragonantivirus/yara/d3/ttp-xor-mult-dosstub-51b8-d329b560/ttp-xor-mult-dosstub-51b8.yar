rule TTP_XOR_MULT_DOSStub_51b8 {
  strings:
    $key_51b8 = { 05 d0 [2] 71 c8 [2] 36 ca [2] 71 db [2] 3f d7 [2] 33 dd [2] 24 d6 [2] 3f 98 [2] 02 }

  condition:
    any of them
}