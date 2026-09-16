rule TTP_XOR_MULT_DOSStub_4f8c {
  strings:
    $key_4f8c = { 1b e4 [2] 6f fc [2] 28 fe [2] 6f ef [2] 21 e3 [2] 2d e9 [2] 3a e2 [2] 21 ac [2] 1c }

  condition:
    any of them
}