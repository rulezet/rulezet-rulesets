rule TTP_XOR_MULT_DOSStub_e79e {
  strings:
    $key_e79e = { b3 f6 [2] c7 ee [2] 80 ec [2] c7 fd [2] 89 f1 [2] 85 fb [2] 92 f0 [2] 89 be [2] b4 }

  condition:
    any of them
}