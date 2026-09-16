rule TTP_XOR_MULT_DOSStub_1e9e {
  strings:
    $key_1e9e = { 4a f6 [2] 3e ee [2] 79 ec [2] 3e fd [2] 70 f1 [2] 7c fb [2] 6b f0 [2] 70 be [2] 4d }

  condition:
    any of them
}