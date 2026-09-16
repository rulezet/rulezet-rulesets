rule TTP_XOR_MULT_DOSStub_7f83 {
  strings:
    $key_7f83 = { 2b eb [2] 5f f3 [2] 18 f1 [2] 5f e0 [2] 11 ec [2] 1d e6 [2] 0a ed [2] 11 a3 [2] 2c }

  condition:
    any of them
}