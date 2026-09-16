rule TTP_XOR_MULT_DOSStub_2bb8 {
  strings:
    $key_2bb8 = { 7f d0 [2] 0b c8 [2] 4c ca [2] 0b db [2] 45 d7 [2] 49 dd [2] 5e d6 [2] 45 98 [2] 78 }

  condition:
    any of them
}