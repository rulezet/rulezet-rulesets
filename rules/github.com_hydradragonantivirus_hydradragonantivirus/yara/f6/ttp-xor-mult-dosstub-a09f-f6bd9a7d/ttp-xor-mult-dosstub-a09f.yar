rule TTP_XOR_MULT_DOSStub_a09f {
  strings:
    $key_a09f = { f4 f7 [2] 80 ef [2] c7 ed [2] 80 fc [2] ce f0 [2] c2 fa [2] d5 f1 [2] ce bf [2] f3 }

  condition:
    any of them
}