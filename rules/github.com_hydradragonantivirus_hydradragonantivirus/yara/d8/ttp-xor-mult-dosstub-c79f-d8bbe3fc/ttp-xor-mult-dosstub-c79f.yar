rule TTP_XOR_MULT_DOSStub_c79f {
  strings:
    $key_c79f = { 93 f7 [2] e7 ef [2] a0 ed [2] e7 fc [2] a9 f0 [2] a5 fa [2] b2 f1 [2] a9 bf [2] 94 }

  condition:
    any of them
}