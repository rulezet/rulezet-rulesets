rule TTP_XOR_MULT_DOSStub_498c {
  strings:
    $key_498c = { 1d e4 [2] 69 fc [2] 2e fe [2] 69 ef [2] 27 e3 [2] 2b e9 [2] 3c e2 [2] 27 ac [2] 1a }

  condition:
    any of them
}