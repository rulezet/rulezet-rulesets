rule TTP_XOR_MULT_DOSStub_7c8a {
  strings:
    $key_7c8a = { 28 e2 [2] 5c fa [2] 1b f8 [2] 5c e9 [2] 12 e5 [2] 1e ef [2] 09 e4 [2] 12 aa [2] 2f }

  condition:
    any of them
}