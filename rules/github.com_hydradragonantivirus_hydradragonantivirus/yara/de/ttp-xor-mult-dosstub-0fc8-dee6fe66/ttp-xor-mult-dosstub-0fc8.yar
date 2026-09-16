rule TTP_XOR_MULT_DOSStub_0fc8 {
  strings:
    $key_0fc8 = { 5b a0 [2] 2f b8 [2] 68 ba [2] 2f ab [2] 61 a7 [2] 6d ad [2] 7a a6 [2] 61 e8 [2] 5c }

  condition:
    any of them
}