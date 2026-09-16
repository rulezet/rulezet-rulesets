rule TTP_XOR_MULT_DOSStub_ecec {
  strings:
    $key_ecec = { b8 84 [2] cc 9c [2] 8b 9e [2] cc 8f [2] 82 83 [2] 8e 89 [2] 99 82 [2] 82 cc [2] bf }

  condition:
    any of them
}