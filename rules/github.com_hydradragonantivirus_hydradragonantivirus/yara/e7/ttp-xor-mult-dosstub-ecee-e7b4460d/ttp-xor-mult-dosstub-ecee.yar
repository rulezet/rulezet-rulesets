rule TTP_XOR_MULT_DOSStub_ecee {
  strings:
    $key_ecee = { b8 86 [2] cc 9e [2] 8b 9c [2] cc 8d [2] 82 81 [2] 8e 8b [2] 99 80 [2] 82 ce [2] bf }

  condition:
    any of them
}