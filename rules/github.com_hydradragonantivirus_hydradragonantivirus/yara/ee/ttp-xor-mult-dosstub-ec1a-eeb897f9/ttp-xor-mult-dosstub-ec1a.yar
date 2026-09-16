rule TTP_XOR_MULT_DOSStub_ec1a {
  strings:
    $key_ec1a = { b8 72 [2] cc 6a [2] 8b 68 [2] cc 79 [2] 82 75 [2] 8e 7f [2] 99 74 [2] 82 3a [2] bf }

  condition:
    any of them
}