rule TTP_XOR_MULT_DOSStub_b88c {
  strings:
    $key_b88c = { ec e4 [2] 98 fc [2] df fe [2] 98 ef [2] d6 e3 [2] da e9 [2] cd e2 [2] d6 ac [2] eb }

  condition:
    any of them
}