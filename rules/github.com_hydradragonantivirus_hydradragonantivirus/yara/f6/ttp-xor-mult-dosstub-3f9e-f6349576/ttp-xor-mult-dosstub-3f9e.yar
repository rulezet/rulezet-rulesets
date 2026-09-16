rule TTP_XOR_MULT_DOSStub_3f9e {
  strings:
    $key_3f9e = { 6b f6 [2] 1f ee [2] 58 ec [2] 1f fd [2] 51 f1 [2] 5d fb [2] 4a f0 [2] 51 be [2] 6c }

  condition:
    any of them
}