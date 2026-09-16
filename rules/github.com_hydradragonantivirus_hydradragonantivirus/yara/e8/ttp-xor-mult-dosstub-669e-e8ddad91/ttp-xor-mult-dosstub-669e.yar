rule TTP_XOR_MULT_DOSStub_669e {
  strings:
    $key_669e = { 32 f6 [2] 46 ee [2] 01 ec [2] 46 fd [2] 08 f1 [2] 04 fb [2] 13 f0 [2] 08 be [2] 35 }

  condition:
    any of them
}