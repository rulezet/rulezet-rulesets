rule TTP_XOR_MULT_DOSStub_b88a {
  strings:
    $key_b88a = { ec e2 [2] 98 fa [2] df f8 [2] 98 e9 [2] d6 e5 [2] da ef [2] cd e4 [2] d6 aa [2] eb }

  condition:
    any of them
}