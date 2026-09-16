rule TTP_XOR_MULT_DOSStub_ece5 {
  strings:
    $key_ece5 = { b8 8d [2] cc 95 [2] 8b 97 [2] cc 86 [2] 82 8a [2] 8e 80 [2] 99 8b [2] 82 c5 [2] bf }

  condition:
    any of them
}