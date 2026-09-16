rule TTP_XOR_MULT_DOSStub_198c {
  strings:
    $key_198c = { 4d e4 [2] 39 fc [2] 7e fe [2] 39 ef [2] 77 e3 [2] 7b e9 [2] 6c e2 [2] 77 ac [2] 4a }

  condition:
    any of them
}