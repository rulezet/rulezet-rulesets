rule TTP_XOR_MULT_DOSStub_ec18 {
  strings:
    $key_ec18 = { b8 70 [2] cc 68 [2] 8b 6a [2] cc 7b [2] 82 77 [2] 8e 7d [2] 99 76 [2] 82 38 [2] bf }

  condition:
    any of them
}