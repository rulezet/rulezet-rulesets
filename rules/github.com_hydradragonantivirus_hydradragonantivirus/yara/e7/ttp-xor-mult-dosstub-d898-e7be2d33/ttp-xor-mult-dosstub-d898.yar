rule TTP_XOR_MULT_DOSStub_d898 {
  strings:
    $key_d898 = { 8c f0 [2] f8 e8 [2] bf ea [2] f8 fb [2] b6 f7 [2] ba fd [2] ad f6 [2] b6 b8 [2] 8b }

  condition:
    any of them
}