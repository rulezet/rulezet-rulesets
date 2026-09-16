rule TTP_XOR_MULT_DOSStub_ec45 {
  strings:
    $key_ec45 = { b8 2d [2] cc 35 [2] 8b 37 [2] cc 26 [2] 82 2a [2] 8e 20 [2] 99 2b [2] 82 65 [2] bf }

  condition:
    any of them
}