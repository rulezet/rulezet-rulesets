rule TTP_XOR_MULT_DOSStub_e59f {
  strings:
    $key_e59f = { b1 f7 [2] c5 ef [2] 82 ed [2] c5 fc [2] 8b f0 [2] 87 fa [2] 90 f1 [2] 8b bf [2] b6 }

  condition:
    any of them
}