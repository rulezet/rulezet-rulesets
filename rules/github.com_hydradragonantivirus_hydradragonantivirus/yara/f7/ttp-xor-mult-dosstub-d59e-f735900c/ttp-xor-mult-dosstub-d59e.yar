rule TTP_XOR_MULT_DOSStub_d59e {
  strings:
    $key_d59e = { 81 f6 [2] f5 ee [2] b2 ec [2] f5 fd [2] bb f1 [2] b7 fb [2] a0 f0 [2] bb be [2] 86 }

  condition:
    any of them
}