rule TTP_XOR_MULT_DOSStub_6f83 {
  strings:
    $key_6f83 = { 3b eb [2] 4f f3 [2] 08 f1 [2] 4f e0 [2] 01 ec [2] 0d e6 [2] 1a ed [2] 01 a3 [2] 3c }

  condition:
    any of them
}