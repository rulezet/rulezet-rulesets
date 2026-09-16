rule TTP_XOR_MULT_DOSStub_7e8c {
  strings:
    $key_7e8c = { 2a e4 [2] 5e fc [2] 19 fe [2] 5e ef [2] 10 e3 [2] 1c e9 [2] 0b e2 [2] 10 ac [2] 2d }

  condition:
    any of them
}