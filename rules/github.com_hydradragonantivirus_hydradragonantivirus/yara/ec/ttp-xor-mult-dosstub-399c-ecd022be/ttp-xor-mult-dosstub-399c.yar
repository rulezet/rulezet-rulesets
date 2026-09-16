rule TTP_XOR_MULT_DOSStub_399c {
  strings:
    $key_399c = { 6d f4 [2] 19 ec [2] 5e ee [2] 19 ff [2] 57 f3 [2] 5b f9 [2] 4c f2 [2] 57 bc [2] 6a }

  condition:
    any of them
}