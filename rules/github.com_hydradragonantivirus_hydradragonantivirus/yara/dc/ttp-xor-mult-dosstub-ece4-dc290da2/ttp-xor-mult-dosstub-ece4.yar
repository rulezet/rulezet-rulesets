rule TTP_XOR_MULT_DOSStub_ece4 {
  strings:
    $key_ece4 = { b8 8c [2] cc 94 [2] 8b 96 [2] cc 87 [2] 82 8b [2] 8e 81 [2] 99 8a [2] 82 c4 [2] bf }

  condition:
    any of them
}