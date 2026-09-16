rule TTP_XOR_MULT_DOSStub_fe8c {
  strings:
    $key_fe8c = { aa e4 [2] de fc [2] 99 fe [2] de ef [2] 90 e3 [2] 9c e9 [2] 8b e2 [2] 90 ac [2] ad }

  condition:
    any of them
}