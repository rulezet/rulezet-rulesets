rule TTP_XOR_MULT_DOSStub_a5b5 {
  strings:
    $key_a5b5 = { f1 dd [2] 85 c5 [2] c2 c7 [2] 85 d6 [2] cb da [2] c7 d0 [2] d0 db [2] cb 95 [2] f6 }

  condition:
    any of them
}