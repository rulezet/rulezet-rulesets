rule TTP_XOR_MULT_DOSStub_809f {
  strings:
    $key_809f = { d4 f7 [2] a0 ef [2] e7 ed [2] a0 fc [2] ee f0 [2] e2 fa [2] f5 f1 [2] ee bf [2] d3 }

  condition:
    any of them
}