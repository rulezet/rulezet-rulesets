rule TTP_XOR_MULT_DOSStub_d498 {
  strings:
    $key_d498 = { 80 f0 [2] f4 e8 [2] b3 ea [2] f4 fb [2] ba f7 [2] b6 fd [2] a1 f6 [2] ba b8 [2] 87 }

  condition:
    any of them
}