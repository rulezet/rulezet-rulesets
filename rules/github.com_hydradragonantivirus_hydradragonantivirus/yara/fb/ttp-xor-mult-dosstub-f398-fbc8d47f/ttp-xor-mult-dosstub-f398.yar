rule TTP_XOR_MULT_DOSStub_f398 {
  strings:
    $key_f398 = { a7 f0 [2] d3 e8 [2] 94 ea [2] d3 fb [2] 9d f7 [2] 91 fd [2] 86 f6 [2] 9d b8 [2] a0 }

  condition:
    any of them
}