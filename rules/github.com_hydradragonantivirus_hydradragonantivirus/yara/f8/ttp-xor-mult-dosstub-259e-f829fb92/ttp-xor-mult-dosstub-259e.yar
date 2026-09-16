rule TTP_XOR_MULT_DOSStub_259e {
  strings:
    $key_259e = { 71 f6 [2] 05 ee [2] 42 ec [2] 05 fd [2] 4b f1 [2] 47 fb [2] 50 f0 [2] 4b be [2] 76 }

  condition:
    any of them
}