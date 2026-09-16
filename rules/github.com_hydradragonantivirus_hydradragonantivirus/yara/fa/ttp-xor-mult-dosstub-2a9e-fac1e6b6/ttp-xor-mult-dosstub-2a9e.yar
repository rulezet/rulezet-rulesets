rule TTP_XOR_MULT_DOSStub_2a9e {
  strings:
    $key_2a9e = { 7e f6 [2] 0a ee [2] 4d ec [2] 0a fd [2] 44 f1 [2] 48 fb [2] 5f f0 [2] 44 be [2] 79 }

  condition:
    any of them
}