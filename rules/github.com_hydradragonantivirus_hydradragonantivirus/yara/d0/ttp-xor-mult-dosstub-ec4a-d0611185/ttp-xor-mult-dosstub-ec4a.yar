rule TTP_XOR_MULT_DOSStub_ec4a {
  strings:
    $key_ec4a = { b8 22 [2] cc 3a [2] 8b 38 [2] cc 29 [2] 82 25 [2] 8e 2f [2] 99 24 [2] 82 6a [2] bf }

  condition:
    any of them
}