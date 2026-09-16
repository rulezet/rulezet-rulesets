rule TTP_XOR_MULT_DOSStub_159c {
  strings:
    $key_159c = { 41 f4 [2] 35 ec [2] 72 ee [2] 35 ff [2] 7b f3 [2] 77 f9 [2] 60 f2 [2] 7b bc [2] 46 }

  condition:
    any of them
}