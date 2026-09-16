rule TTP_XOR_MULT_DOSStub_0983 {
  strings:
    $key_0983 = { 5d eb [2] 29 f3 [2] 6e f1 [2] 29 e0 [2] 67 ec [2] 6b e6 [2] 7c ed [2] 67 a3 [2] 5a }

  condition:
    any of them
}