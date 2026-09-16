rule TTP_XOR_MULT_DOSStub_51b3 {
  strings:
    $key_51b3 = { 05 db [2] 71 c3 [2] 36 c1 [2] 71 d0 [2] 3f dc [2] 33 d6 [2] 24 dd [2] 3f 93 [2] 02 }

  condition:
    any of them
}