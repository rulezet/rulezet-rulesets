rule TTP_XOR_MULT_DOSStub_eceb {
  strings:
    $key_eceb = { b8 83 [2] cc 9b [2] 8b 99 [2] cc 88 [2] 82 84 [2] 8e 8e [2] 99 85 [2] 82 cb [2] bf }

  condition:
    any of them
}