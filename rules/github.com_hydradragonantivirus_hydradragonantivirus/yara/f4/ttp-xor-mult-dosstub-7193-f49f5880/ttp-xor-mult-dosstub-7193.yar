rule TTP_XOR_MULT_DOSStub_7193 {
  strings:
    $key_7193 = { 25 fb [2] 51 e3 [2] 16 e1 [2] 51 f0 [2] 1f fc [2] 13 f6 [2] 04 fd [2] 1f b3 [2] 22 }

  condition:
    any of them
}