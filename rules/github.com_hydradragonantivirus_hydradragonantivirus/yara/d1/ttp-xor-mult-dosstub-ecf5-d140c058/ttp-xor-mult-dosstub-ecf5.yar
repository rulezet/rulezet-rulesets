rule TTP_XOR_MULT_DOSStub_ecf5 {
  strings:
    $key_ecf5 = { b8 9d [2] cc 85 [2] 8b 87 [2] cc 96 [2] 82 9a [2] 8e 90 [2] 99 9b [2] 82 d5 [2] bf }

  condition:
    any of them
}