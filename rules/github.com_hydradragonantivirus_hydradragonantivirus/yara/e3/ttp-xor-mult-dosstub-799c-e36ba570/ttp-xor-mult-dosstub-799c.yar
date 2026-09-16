rule TTP_XOR_MULT_DOSStub_799c {
  strings:
    $key_799c = { 2d f4 [2] 59 ec [2] 1e ee [2] 59 ff [2] 17 f3 [2] 1b f9 [2] 0c f2 [2] 17 bc [2] 2a }

  condition:
    any of them
}