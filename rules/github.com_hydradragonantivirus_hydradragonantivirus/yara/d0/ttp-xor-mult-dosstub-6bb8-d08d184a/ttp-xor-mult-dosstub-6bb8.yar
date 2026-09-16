rule TTP_XOR_MULT_DOSStub_6bb8 {
  strings:
    $key_6bb8 = { 3f d0 [2] 4b c8 [2] 0c ca [2] 4b db [2] 05 d7 [2] 09 dd [2] 1e d6 [2] 05 98 [2] 38 }

  condition:
    any of them
}