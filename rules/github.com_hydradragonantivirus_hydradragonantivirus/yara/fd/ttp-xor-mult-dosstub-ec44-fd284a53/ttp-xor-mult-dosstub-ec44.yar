rule TTP_XOR_MULT_DOSStub_ec44 {
  strings:
    $key_ec44 = { b8 2c [2] cc 34 [2] 8b 36 [2] cc 27 [2] 82 2b [2] 8e 21 [2] 99 2a [2] 82 64 [2] bf }

  condition:
    any of them
}