rule TTP_XOR_MULT_DOSStub_f79f {
  strings:
    $key_f79f = { a3 f7 [2] d7 ef [2] 90 ed [2] d7 fc [2] 99 f0 [2] 95 fa [2] 82 f1 [2] 99 bf [2] a4 }

  condition:
    any of them
}