rule TTP_XOR_MULT_DOSStub_a49f {
  strings:
    $key_a49f = { f0 f7 [2] 84 ef [2] c3 ed [2] 84 fc [2] ca f0 [2] c6 fa [2] d1 f1 [2] ca bf [2] f7 }

  condition:
    any of them
}