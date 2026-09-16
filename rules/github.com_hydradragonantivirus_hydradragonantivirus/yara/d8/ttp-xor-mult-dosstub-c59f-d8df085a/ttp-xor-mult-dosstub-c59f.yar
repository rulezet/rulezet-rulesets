rule TTP_XOR_MULT_DOSStub_c59f {
  strings:
    $key_c59f = { 91 f7 [2] e5 ef [2] a2 ed [2] e5 fc [2] ab f0 [2] a7 fa [2] b0 f1 [2] ab bf [2] 96 }

  condition:
    any of them
}