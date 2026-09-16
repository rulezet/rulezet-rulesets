rule TTP_XOR_MULT_DOSStub_d298 {
  strings:
    $key_d298 = { 86 f0 [2] f2 e8 [2] b5 ea [2] f2 fb [2] bc f7 [2] b0 fd [2] a7 f6 [2] bc b8 [2] 81 }

  condition:
    any of them
}