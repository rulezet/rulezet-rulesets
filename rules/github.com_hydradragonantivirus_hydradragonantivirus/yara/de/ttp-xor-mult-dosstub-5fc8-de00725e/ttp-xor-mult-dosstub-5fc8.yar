rule TTP_XOR_MULT_DOSStub_5fc8 {
  strings:
    $key_5fc8 = { 0b a0 [2] 7f b8 [2] 38 ba [2] 7f ab [2] 31 a7 [2] 3d ad [2] 2a a6 [2] 31 e8 [2] 0c }

  condition:
    any of them
}