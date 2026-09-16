rule TTP_XOR_MULT_DOSStub_299f {
  strings:
    $key_299f = { 7d f7 [2] 09 ef [2] 4e ed [2] 09 fc [2] 47 f0 [2] 4b fa [2] 5c f1 [2] 47 bf [2] 7a }

  condition:
    any of them
}