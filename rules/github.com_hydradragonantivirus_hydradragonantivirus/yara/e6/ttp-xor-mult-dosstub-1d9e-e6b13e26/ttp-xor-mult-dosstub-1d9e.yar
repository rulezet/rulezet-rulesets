rule TTP_XOR_MULT_DOSStub_1d9e {
  strings:
    $key_1d9e = { 49 f6 [2] 3d ee [2] 7a ec [2] 3d fd [2] 73 f1 [2] 7f fb [2] 68 f0 [2] 73 be [2] 4e }

  condition:
    any of them
}