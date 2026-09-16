rule TTP_XOR_MULT_DOSStub_a59f {
  strings:
    $key_a59f = { f1 f7 [2] 85 ef [2] c2 ed [2] 85 fc [2] cb f0 [2] c7 fa [2] d0 f1 [2] cb bf [2] f6 }

  condition:
    any of them
}