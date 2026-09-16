rule TTP_XOR_MULT_DOSStub_6b9e {
  strings:
    $key_6b9e = { 3f f6 [2] 4b ee [2] 0c ec [2] 4b fd [2] 05 f1 [2] 09 fb [2] 1e f0 [2] 05 be [2] 38 }

  condition:
    any of them
}