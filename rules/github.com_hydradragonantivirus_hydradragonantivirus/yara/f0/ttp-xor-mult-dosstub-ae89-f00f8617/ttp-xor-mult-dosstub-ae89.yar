rule TTP_XOR_MULT_DOSStub_ae89 {
  strings:
    $key_ae89 = { fa e1 [2] 8e f9 [2] c9 fb [2] 8e ea [2] c0 e6 [2] cc ec [2] db e7 [2] c0 a9 [2] fd }

  condition:
    any of them
}