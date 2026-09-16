rule TTP_XOR_MULT_DOSStub_3fc8 {
  strings:
    $key_3fc8 = { 6b a0 [2] 1f b8 [2] 58 ba [2] 1f ab [2] 51 a7 [2] 5d ad [2] 4a a6 [2] 51 e8 [2] 6c }

  condition:
    any of them
}