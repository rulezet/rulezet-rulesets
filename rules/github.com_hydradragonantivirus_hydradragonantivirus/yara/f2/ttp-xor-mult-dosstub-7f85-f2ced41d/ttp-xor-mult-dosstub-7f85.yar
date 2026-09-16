rule TTP_XOR_MULT_DOSStub_7f85 {
  strings:
    $key_7f85 = { 2b ed [2] 5f f5 [2] 18 f7 [2] 5f e6 [2] 11 ea [2] 1d e0 [2] 0a eb [2] 11 a5 [2] 2c }

  condition:
    any of them
}