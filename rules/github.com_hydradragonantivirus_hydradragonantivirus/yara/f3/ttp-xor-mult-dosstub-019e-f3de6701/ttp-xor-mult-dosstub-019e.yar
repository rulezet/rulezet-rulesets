rule TTP_XOR_MULT_DOSStub_019e {
  strings:
    $key_019e = { 55 f6 [2] 21 ee [2] 66 ec [2] 21 fd [2] 6f f1 [2] 63 fb [2] 74 f0 [2] 6f be [2] 52 }

  condition:
    any of them
}