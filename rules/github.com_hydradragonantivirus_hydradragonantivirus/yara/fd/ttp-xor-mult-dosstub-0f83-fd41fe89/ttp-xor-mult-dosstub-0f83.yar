rule TTP_XOR_MULT_DOSStub_0f83 {
  strings:
    $key_0f83 = { 5b eb [2] 2f f3 [2] 68 f1 [2] 2f e0 [2] 61 ec [2] 6d e6 [2] 7a ed [2] 61 a3 [2] 5c }

  condition:
    any of them
}