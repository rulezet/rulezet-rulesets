rule TTP_XOR_MULT_DOSStub_4e9e {
  strings:
    $key_4e9e = { 1a f6 [2] 6e ee [2] 29 ec [2] 6e fd [2] 20 f1 [2] 2c fb [2] 3b f0 [2] 20 be [2] 1d }

  condition:
    any of them
}