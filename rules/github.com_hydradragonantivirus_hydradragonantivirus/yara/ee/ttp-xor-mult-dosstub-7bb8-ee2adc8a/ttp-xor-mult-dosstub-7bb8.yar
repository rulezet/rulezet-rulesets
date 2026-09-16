rule TTP_XOR_MULT_DOSStub_7bb8 {
  strings:
    $key_7bb8 = { 2f d0 [2] 5b c8 [2] 1c ca [2] 5b db [2] 15 d7 [2] 19 dd [2] 0e d6 [2] 15 98 [2] 28 }

  condition:
    any of them
}