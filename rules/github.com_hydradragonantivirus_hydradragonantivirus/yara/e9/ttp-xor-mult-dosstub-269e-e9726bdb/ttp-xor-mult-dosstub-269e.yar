rule TTP_XOR_MULT_DOSStub_269e {
  strings:
    $key_269e = { 72 f6 [2] 06 ee [2] 41 ec [2] 06 fd [2] 48 f1 [2] 44 fb [2] 53 f0 [2] 48 be [2] 75 }

  condition:
    any of them
}