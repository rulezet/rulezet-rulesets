rule TTP_XOR_MULT_DOSStub_5d9d {
  strings:
    $key_5d9d = { 09 f5 [2] 7d ed [2] 3a ef [2] 7d fe [2] 33 f2 [2] 3f f8 [2] 28 f3 [2] 33 bd [2] 0e }

  condition:
    any of them
}