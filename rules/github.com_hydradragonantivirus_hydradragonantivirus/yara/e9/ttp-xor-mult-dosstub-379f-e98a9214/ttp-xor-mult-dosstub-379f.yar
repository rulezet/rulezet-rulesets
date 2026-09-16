rule TTP_XOR_MULT_DOSStub_379f {
  strings:
    $key_379f = { 63 f7 [2] 17 ef [2] 50 ed [2] 17 fc [2] 59 f0 [2] 55 fa [2] 42 f1 [2] 59 bf [2] 64 }

  condition:
    any of them
}