rule TTP_XOR_MULT_DOSStub_db81 {
  strings:
    $key_db81 = { 8f e9 [2] fb f1 [2] bc f3 [2] fb e2 [2] b5 ee [2] b9 e4 [2] ae ef [2] b5 a1 [2] 88 }

  condition:
    any of them
}