rule TTP_XOR_MULT_DOSStub_ecf0 {
  strings:
    $key_ecf0 = { b8 98 [2] cc 80 [2] 8b 82 [2] cc 93 [2] 82 9f [2] 8e 95 [2] 99 9e [2] 82 d0 [2] bf }

  condition:
    any of them
}