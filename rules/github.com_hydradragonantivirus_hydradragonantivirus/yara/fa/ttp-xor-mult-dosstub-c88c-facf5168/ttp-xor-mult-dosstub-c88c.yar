rule TTP_XOR_MULT_DOSStub_c88c {
  strings:
    $key_c88c = { 9c e4 [2] e8 fc [2] af fe [2] e8 ef [2] a6 e3 [2] aa e9 [2] bd e2 [2] a6 ac [2] 9b }

  condition:
    any of them
}