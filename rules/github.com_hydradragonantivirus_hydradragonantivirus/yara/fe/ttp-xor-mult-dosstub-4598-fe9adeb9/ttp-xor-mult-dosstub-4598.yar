rule TTP_XOR_MULT_DOSStub_4598 {
  strings:
    $key_4598 = { 11 f0 [2] 65 e8 [2] 22 ea [2] 65 fb [2] 2b f7 [2] 27 fd [2] 30 f6 [2] 2b b8 [2] 16 }

  condition:
    any of them
}