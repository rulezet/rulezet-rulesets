rule TTP_XOR_MULT_DOSStub_088c {
  strings:
    $key_088c = { 5c e4 [2] 28 fc [2] 6f fe [2] 28 ef [2] 66 e3 [2] 6a e9 [2] 7d e2 [2] 66 ac [2] 5b }

  condition:
    any of them
}