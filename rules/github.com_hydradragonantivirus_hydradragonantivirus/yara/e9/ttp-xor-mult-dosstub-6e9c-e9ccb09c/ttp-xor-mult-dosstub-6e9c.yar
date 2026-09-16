rule TTP_XOR_MULT_DOSStub_6e9c {
  strings:
    $key_6e9c = { 3a f4 [2] 4e ec [2] 09 ee [2] 4e ff [2] 00 f3 [2] 0c f9 [2] 1b f2 [2] 00 bc [2] 3d }

  condition:
    any of them
}