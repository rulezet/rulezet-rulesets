rule TTP_XOR_MULT_DOSStub_7b83 {
  strings:
    $key_7b83 = { 2f eb [2] 5b f3 [2] 1c f1 [2] 5b e0 [2] 15 ec [2] 19 e6 [2] 0e ed [2] 15 a3 [2] 28 }

  condition:
    any of them
}