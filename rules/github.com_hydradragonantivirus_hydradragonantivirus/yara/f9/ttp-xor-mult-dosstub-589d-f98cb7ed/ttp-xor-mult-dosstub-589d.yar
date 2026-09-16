rule TTP_XOR_MULT_DOSStub_589d {
  strings:
    $key_589d = { 0c f5 [2] 78 ed [2] 3f ef [2] 78 fe [2] 36 f2 [2] 3a f8 [2] 2d f3 [2] 36 bd [2] 0b }

  condition:
    any of them
}