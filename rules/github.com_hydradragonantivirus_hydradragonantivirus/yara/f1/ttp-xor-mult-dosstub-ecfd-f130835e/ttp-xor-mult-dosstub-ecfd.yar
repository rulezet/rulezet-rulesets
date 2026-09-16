rule TTP_XOR_MULT_DOSStub_ecfd {
  strings:
    $key_ecfd = { b8 95 [2] cc 8d [2] 8b 8f [2] cc 9e [2] 82 92 [2] 8e 98 [2] 99 93 [2] 82 dd [2] bf }

  condition:
    any of them
}