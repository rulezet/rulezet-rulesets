rule TTP_XOR_MULT_DOSStub_4c9c {
  strings:
    $key_4c9c = { 18 f4 [2] 6c ec [2] 2b ee [2] 6c ff [2] 22 f3 [2] 2e f9 [2] 39 f2 [2] 22 bc [2] 1f }

  condition:
    any of them
}