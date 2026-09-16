rule TTP_XOR_MULT_DOSStub_2d9e {
  strings:
    $key_2d9e = { 79 f6 [2] 0d ee [2] 4a ec [2] 0d fd [2] 43 f1 [2] 4f fb [2] 58 f0 [2] 43 be [2] 7e }

  condition:
    any of them
}