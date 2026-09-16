rule TTP_XOR_MULT_DOSStub_a79f {
  strings:
    $key_a79f = { f3 f7 [2] 87 ef [2] c0 ed [2] 87 fc [2] c9 f0 [2] c5 fa [2] d2 f1 [2] c9 bf [2] f4 }

  condition:
    any of them
}