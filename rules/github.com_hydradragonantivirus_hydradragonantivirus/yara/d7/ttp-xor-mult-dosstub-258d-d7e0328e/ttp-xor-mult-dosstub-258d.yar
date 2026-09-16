rule TTP_XOR_MULT_DOSStub_258d {
  strings:
    $key_258d = { 71 e5 [2] 05 fd [2] 42 ff [2] 05 ee [2] 4b e2 [2] 47 e8 [2] 50 e3 [2] 4b ad [2] 76 }

  condition:
    any of them
}