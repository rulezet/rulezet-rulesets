rule TTP_XOR_MULT_DOSStub_0e9d {
  strings:
    $key_0e9d = { 5a f5 [2] 2e ed [2] 69 ef [2] 2e fe [2] 60 f2 [2] 6c f8 [2] 7b f3 [2] 60 bd [2] 5d }

  condition:
    any of them
}