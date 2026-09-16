rule TTP_XOR_MULT_DOSStub_e59e {
  strings:
    $key_e59e = { b1 f6 [2] c5 ee [2] 82 ec [2] c5 fd [2] 8b f1 [2] 87 fb [2] 90 f0 [2] 8b be [2] b6 }

  condition:
    any of them
}