rule TTP_XOR_MULT_DOSStub_51b2 {
  strings:
    $key_51b2 = { 05 da [2] 71 c2 [2] 36 c0 [2] 71 d1 [2] 3f dd [2] 33 d7 [2] 24 dc [2] 3f 92 [2] 02 }

  condition:
    any of them
}