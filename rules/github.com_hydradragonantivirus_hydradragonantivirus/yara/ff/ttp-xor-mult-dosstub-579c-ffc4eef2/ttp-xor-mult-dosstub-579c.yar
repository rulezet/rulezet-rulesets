rule TTP_XOR_MULT_DOSStub_579c {
  strings:
    $key_579c = { 03 f4 [2] 77 ec [2] 30 ee [2] 77 ff [2] 39 f3 [2] 35 f9 [2] 22 f2 [2] 39 bc [2] 04 }

  condition:
    any of them
}