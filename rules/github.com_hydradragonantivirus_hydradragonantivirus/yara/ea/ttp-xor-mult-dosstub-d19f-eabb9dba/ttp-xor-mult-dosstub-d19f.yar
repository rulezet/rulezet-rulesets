rule TTP_XOR_MULT_DOSStub_d19f {
  strings:
    $key_d19f = { 85 f7 [2] f1 ef [2] b6 ed [2] f1 fc [2] bf f0 [2] b3 fa [2] a4 f1 [2] bf bf [2] 82 }

  condition:
    any of them
}