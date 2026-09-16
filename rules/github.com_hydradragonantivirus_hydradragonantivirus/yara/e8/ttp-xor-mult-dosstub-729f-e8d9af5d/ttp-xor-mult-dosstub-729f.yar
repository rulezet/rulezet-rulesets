rule TTP_XOR_MULT_DOSStub_729f {
  strings:
    $key_729f = { 26 f7 [2] 52 ef [2] 15 ed [2] 52 fc [2] 1c f0 [2] 10 fa [2] 07 f1 [2] 1c bf [2] 21 }

  condition:
    any of them
}