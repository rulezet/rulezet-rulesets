rule TTP_XOR_MULT_DOSStub_5eb2 {
  strings:
    $key_5eb2 = { 0a da [2] 7e c2 [2] 39 c0 [2] 7e d1 [2] 30 dd [2] 3c d7 [2] 2b dc [2] 30 92 [2] 0d }

  condition:
    any of them
}