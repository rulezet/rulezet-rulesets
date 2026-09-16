rule TTP_XOR_MULT_DOSStub_ec02 {
  strings:
    $key_ec02 = { b8 6a [2] cc 72 [2] 8b 70 [2] cc 61 [2] 82 6d [2] 8e 67 [2] 99 6c [2] 82 22 [2] bf }

  condition:
    any of them
}