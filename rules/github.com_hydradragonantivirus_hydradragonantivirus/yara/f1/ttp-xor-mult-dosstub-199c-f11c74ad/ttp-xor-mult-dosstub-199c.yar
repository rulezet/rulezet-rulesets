rule TTP_XOR_MULT_DOSStub_199c {
  strings:
    $key_199c = { 4d f4 [2] 39 ec [2] 7e ee [2] 39 ff [2] 77 f3 [2] 7b f9 [2] 6c f2 [2] 77 bc [2] 4a }

  condition:
    any of them
}