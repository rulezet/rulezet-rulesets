rule TTP_XOR_MULT_DOSStub_ae94 {
  strings:
    $key_ae94 = { fa fc [2] 8e e4 [2] c9 e6 [2] 8e f7 [2] c0 fb [2] cc f1 [2] db fa [2] c0 b4 [2] fd }

  condition:
    any of them
}