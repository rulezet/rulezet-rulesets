rule TTP_XOR_MULT_DOSStub_1fc8 {
  strings:
    $key_1fc8 = { 4b a0 [2] 3f b8 [2] 78 ba [2] 3f ab [2] 71 a7 [2] 7d ad [2] 6a a6 [2] 71 e8 [2] 4c }

  condition:
    any of them
}