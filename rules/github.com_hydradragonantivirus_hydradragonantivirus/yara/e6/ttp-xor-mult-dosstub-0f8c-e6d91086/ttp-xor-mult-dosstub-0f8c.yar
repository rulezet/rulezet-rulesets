rule TTP_XOR_MULT_DOSStub_0f8c {
  strings:
    $key_0f8c = { 5b e4 [2] 2f fc [2] 68 fe [2] 2f ef [2] 61 e3 [2] 6d e9 [2] 7a e2 [2] 61 ac [2] 5c }

  condition:
    any of them
}