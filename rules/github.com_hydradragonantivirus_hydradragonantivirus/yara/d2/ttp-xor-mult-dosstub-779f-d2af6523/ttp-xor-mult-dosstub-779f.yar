rule TTP_XOR_MULT_DOSStub_779f {
  strings:
    $key_779f = { 23 f7 [2] 57 ef [2] 10 ed [2] 57 fc [2] 19 f0 [2] 15 fa [2] 02 f1 [2] 19 bf [2] 24 }

  condition:
    any of them
}