rule TTP_XOR_MULT_DOSStub_7a87 {
  strings:
    $key_7a87 = { 2e ef [2] 5a f7 [2] 1d f5 [2] 5a e4 [2] 14 e8 [2] 18 e2 [2] 0f e9 [2] 14 a7 [2] 29 }

  condition:
    any of them
}