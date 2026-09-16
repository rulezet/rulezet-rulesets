rule TTP_XOR_MULT_DOSStub_6e8c {
  strings:
    $key_6e8c = { 3a e4 [2] 4e fc [2] 09 fe [2] 4e ef [2] 00 e3 [2] 0c e9 [2] 1b e2 [2] 00 ac [2] 3d }

  condition:
    any of them
}