rule TTP_XOR_MULT_DOSStub_aec6 {
  strings:
    $key_aec6 = { fa ae [2] 8e b6 [2] c9 b4 [2] 8e a5 [2] c0 a9 [2] cc a3 [2] db a8 [2] c0 e6 [2] fd }

  condition:
    any of them
}