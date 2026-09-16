rule TTP_XOR_MULT_DOSStub_2a80 {
  strings:
    $key_2a80 = { 7e e8 [2] 0a f0 [2] 4d f2 [2] 0a e3 [2] 44 ef [2] 48 e5 [2] 5f ee [2] 44 a0 [2] 79 }

  condition:
    any of them
}