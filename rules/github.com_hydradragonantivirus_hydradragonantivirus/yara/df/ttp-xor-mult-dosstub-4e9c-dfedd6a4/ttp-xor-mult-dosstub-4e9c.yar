rule TTP_XOR_MULT_DOSStub_4e9c {
  strings:
    $key_4e9c = { 1a f4 [2] 6e ec [2] 29 ee [2] 6e ff [2] 20 f3 [2] 2c f9 [2] 3b f2 [2] 20 bc [2] 1d }

  condition:
    any of them
}