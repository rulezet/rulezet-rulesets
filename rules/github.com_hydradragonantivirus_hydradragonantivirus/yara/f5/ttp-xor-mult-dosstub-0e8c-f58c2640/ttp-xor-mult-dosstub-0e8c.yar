rule TTP_XOR_MULT_DOSStub_0e8c {
  strings:
    $key_0e8c = { 5a e4 [2] 2e fc [2] 69 fe [2] 2e ef [2] 60 e3 [2] 6c e9 [2] 7b e2 [2] 60 ac [2] 5d }

  condition:
    any of them
}