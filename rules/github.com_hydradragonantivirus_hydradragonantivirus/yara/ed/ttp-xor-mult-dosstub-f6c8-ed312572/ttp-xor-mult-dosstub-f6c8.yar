rule TTP_XOR_MULT_DOSStub_f6c8 {
  strings:
    $key_f6c8 = { a2 a0 [2] d6 b8 [2] 91 ba [2] d6 ab [2] 98 a7 [2] 94 ad [2] 83 a6 [2] 98 e8 [2] a5 }

  condition:
    any of them
}