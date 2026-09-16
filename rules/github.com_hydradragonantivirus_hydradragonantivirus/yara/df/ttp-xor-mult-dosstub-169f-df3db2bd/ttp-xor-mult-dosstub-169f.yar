rule TTP_XOR_MULT_DOSStub_169f {
  strings:
    $key_169f = { 42 f7 [2] 36 ef [2] 71 ed [2] 36 fc [2] 78 f0 [2] 74 fa [2] 63 f1 [2] 78 bf [2] 45 }

  condition:
    any of them
}