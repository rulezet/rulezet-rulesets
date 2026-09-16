rule TTP_XOR_MULT_DOSStub_51b5 {
  strings:
    $key_51b5 = { 05 dd [2] 71 c5 [2] 36 c7 [2] 71 d6 [2] 3f da [2] 33 d0 [2] 24 db [2] 3f 95 [2] 02 }

  condition:
    any of them
}