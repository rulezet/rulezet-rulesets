rule TTP_XOR_MULT_DOSStub_079f {
  strings:
    $key_079f = { 53 f7 [2] 27 ef [2] 60 ed [2] 27 fc [2] 69 f0 [2] 65 fa [2] 72 f1 [2] 69 bf [2] 54 }

  condition:
    any of them
}