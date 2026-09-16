rule TTP_XOR_MULT_DOSStub_ec24 {
  strings:
    $key_ec24 = { b8 4c [2] cc 54 [2] 8b 56 [2] cc 47 [2] 82 4b [2] 8e 41 [2] 99 4a [2] 82 04 [2] bf }

  condition:
    any of them
}