rule TTP_XOR_MULT_DOSStub_44b5 {
  strings:
    $key_44b5 = { 10 dd [2] 64 c5 [2] 23 c7 [2] 64 d6 [2] 2a da [2] 26 d0 [2] 31 db [2] 2a 95 [2] 17 }

  condition:
    any of them
}