rule TTP_XOR_MULT_DOSStub_049c {
  strings:
    $key_049c = { 50 f4 [2] 24 ec [2] 63 ee [2] 24 ff [2] 6a f3 [2] 66 f9 [2] 71 f2 [2] 6a bc [2] 57 }

  condition:
    any of them
}