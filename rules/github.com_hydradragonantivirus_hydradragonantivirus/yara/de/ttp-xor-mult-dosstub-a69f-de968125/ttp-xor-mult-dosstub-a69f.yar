rule TTP_XOR_MULT_DOSStub_a69f {
  strings:
    $key_a69f = { f2 f7 [2] 86 ef [2] c1 ed [2] 86 fc [2] c8 f0 [2] c4 fa [2] d3 f1 [2] c8 bf [2] f5 }

  condition:
    any of them
}