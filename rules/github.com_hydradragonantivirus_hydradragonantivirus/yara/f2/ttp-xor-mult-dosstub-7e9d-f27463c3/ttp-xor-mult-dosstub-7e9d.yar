rule TTP_XOR_MULT_DOSStub_7e9d {
  strings:
    $key_7e9d = { 2a f5 [2] 5e ed [2] 19 ef [2] 5e fe [2] 10 f2 [2] 1c f8 [2] 0b f3 [2] 10 bd [2] 2d }

  condition:
    any of them
}