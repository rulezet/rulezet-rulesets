rule TTP_XOR_MULT_DOSStub_849f {
  strings:
    $key_849f = { d0 f7 [2] a4 ef [2] e3 ed [2] a4 fc [2] ea f0 [2] e6 fa [2] f1 f1 [2] ea bf [2] d7 }

  condition:
    any of them
}