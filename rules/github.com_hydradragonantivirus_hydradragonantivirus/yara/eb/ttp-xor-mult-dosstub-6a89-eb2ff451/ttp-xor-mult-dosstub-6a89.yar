rule TTP_XOR_MULT_DOSStub_6a89 {
  strings:
    $key_6a89 = { 3e e1 [2] 4a f9 [2] 0d fb [2] 4a ea [2] 04 e6 [2] 08 ec [2] 1f e7 [2] 04 a9 [2] 39 }

  condition:
    any of them
}