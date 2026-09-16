rule TTP_XOR_MULT_DOSStub_7a9c {
  strings:
    $key_7a9c = { 2e f4 [2] 5a ec [2] 1d ee [2] 5a ff [2] 14 f3 [2] 18 f9 [2] 0f f2 [2] 14 bc [2] 29 }

  condition:
    any of them
}