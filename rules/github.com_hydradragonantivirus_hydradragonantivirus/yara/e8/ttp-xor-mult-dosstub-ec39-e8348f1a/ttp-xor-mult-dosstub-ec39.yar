rule TTP_XOR_MULT_DOSStub_ec39 {
  strings:
    $key_ec39 = { b8 51 [2] cc 49 [2] 8b 4b [2] cc 5a [2] 82 56 [2] 8e 5c [2] 99 57 [2] 82 19 [2] bf }

  condition:
    any of them
}