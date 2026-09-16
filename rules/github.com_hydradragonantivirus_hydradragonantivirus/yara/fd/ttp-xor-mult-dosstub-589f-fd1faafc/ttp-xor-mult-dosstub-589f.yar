rule TTP_XOR_MULT_DOSStub_589f {
  strings:
    $key_589f = { 0c f7 [2] 78 ef [2] 3f ed [2] 78 fc [2] 36 f0 [2] 3a fa [2] 2d f1 [2] 36 bf [2] 0b }

  condition:
    any of them
}