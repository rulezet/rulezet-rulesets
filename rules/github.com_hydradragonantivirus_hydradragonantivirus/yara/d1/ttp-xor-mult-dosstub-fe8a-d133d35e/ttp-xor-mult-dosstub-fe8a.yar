rule TTP_XOR_MULT_DOSStub_fe8a {
  strings:
    $key_fe8a = { aa e2 [2] de fa [2] 99 f8 [2] de e9 [2] 90 e5 [2] 9c ef [2] 8b e4 [2] 90 aa [2] ad }

  condition:
    any of them
}