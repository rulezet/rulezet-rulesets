rule TTP_XOR_MULT_DOSStub_939f {
  strings:
    $key_939f = { c7 f7 [2] b3 ef [2] f4 ed [2] b3 fc [2] fd f0 [2] f1 fa [2] e6 f1 [2] fd bf [2] c0 }

  condition:
    any of them
}