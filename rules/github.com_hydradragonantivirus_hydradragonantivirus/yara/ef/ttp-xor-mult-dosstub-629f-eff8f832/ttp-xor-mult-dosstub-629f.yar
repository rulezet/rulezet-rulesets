rule TTP_XOR_MULT_DOSStub_629f {
  strings:
    $key_629f = { 36 f7 [2] 42 ef [2] 05 ed [2] 42 fc [2] 0c f0 [2] 00 fa [2] 17 f1 [2] 0c bf [2] 31 }

  condition:
    any of them
}