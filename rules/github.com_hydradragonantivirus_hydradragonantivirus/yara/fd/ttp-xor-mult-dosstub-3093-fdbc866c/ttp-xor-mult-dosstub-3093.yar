rule TTP_XOR_MULT_DOSStub_3093 {
  strings:
    $key_3093 = { 64 fb [2] 10 e3 [2] 57 e1 [2] 10 f0 [2] 5e fc [2] 52 f6 [2] 45 fd [2] 5e b3 [2] 63 }

  condition:
    any of them
}