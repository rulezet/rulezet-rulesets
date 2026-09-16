rule TTP_XOR_MULT_DOSStub_2b9e {
  strings:
    $key_2b9e = { 7f f6 [2] 0b ee [2] 4c ec [2] 0b fd [2] 45 f1 [2] 49 fb [2] 5e f0 [2] 45 be [2] 78 }

  condition:
    any of them
}