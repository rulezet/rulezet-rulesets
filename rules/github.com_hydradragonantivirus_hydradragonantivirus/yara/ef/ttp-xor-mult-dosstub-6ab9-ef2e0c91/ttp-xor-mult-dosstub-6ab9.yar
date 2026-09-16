rule TTP_XOR_MULT_DOSStub_6ab9 {
  strings:
    $key_6ab9 = { 3e d1 [2] 4a c9 [2] 0d cb [2] 4a da [2] 04 d6 [2] 08 dc [2] 1f d7 [2] 04 99 [2] 39 }

  condition:
    any of them
}