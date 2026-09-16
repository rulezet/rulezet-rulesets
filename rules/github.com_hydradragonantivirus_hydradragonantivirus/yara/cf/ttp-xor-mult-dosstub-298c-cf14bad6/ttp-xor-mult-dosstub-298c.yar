rule TTP_XOR_MULT_DOSStub_298c {
  strings:
    $key_298c = { 7d e4 [2] 09 fc [2] 4e fe [2] 09 ef [2] 47 e3 [2] 4b e9 [2] 5c e2 [2] 47 ac [2] 7a }

  condition:
    any of them
}