rule TTP_XOR_MULT_DOSStub_919f {
  strings:
    $key_919f = { c5 f7 [2] b1 ef [2] f6 ed [2] b1 fc [2] ff f0 [2] f3 fa [2] e4 f1 [2] ff bf [2] c2 }

  condition:
    any of them
}