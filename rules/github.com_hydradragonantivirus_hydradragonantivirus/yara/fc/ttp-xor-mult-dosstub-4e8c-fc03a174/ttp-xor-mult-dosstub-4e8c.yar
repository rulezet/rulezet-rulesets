rule TTP_XOR_MULT_DOSStub_4e8c {
  strings:
    $key_4e8c = { 1a e4 [2] 6e fc [2] 29 fe [2] 6e ef [2] 20 e3 [2] 2c e9 [2] 3b e2 [2] 20 ac [2] 1d }

  condition:
    any of them
}