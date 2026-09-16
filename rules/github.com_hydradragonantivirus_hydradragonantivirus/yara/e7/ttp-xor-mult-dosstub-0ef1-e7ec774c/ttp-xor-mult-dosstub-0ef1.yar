rule TTP_XOR_MULT_DOSStub_0ef1 {
  strings:
    $key_0ef1 = { 5a 99 [2] 2e 81 [2] 69 83 [2] 2e 92 [2] 60 9e [2] 6c 94 [2] 7b 9f [2] 60 d1 [2] 5d }

  condition:
    any of them
}