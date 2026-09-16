rule TTP_XOR_MULT_DOSStub_7d83 {
  strings:
    $key_7d83 = { 29 eb [2] 5d f3 [2] 1a f1 [2] 5d e0 [2] 13 ec [2] 1f e6 [2] 08 ed [2] 13 a3 [2] 2e }

  condition:
    any of them
}