rule TTP_XOR_MULT_DOSStub_609e {
  strings:
    $key_609e = { 34 f6 [2] 40 ee [2] 07 ec [2] 40 fd [2] 0e f1 [2] 02 fb [2] 15 f0 [2] 0e be [2] 33 }

  condition:
    any of them
}