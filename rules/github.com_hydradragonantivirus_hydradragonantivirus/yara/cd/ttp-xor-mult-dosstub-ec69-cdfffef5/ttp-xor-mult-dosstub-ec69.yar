rule TTP_XOR_MULT_DOSStub_ec69 {
  strings:
    $key_ec69 = { b8 01 [2] cc 19 [2] 8b 1b [2] cc 0a [2] 82 06 [2] 8e 0c [2] 99 07 [2] 82 49 [2] bf }

  condition:
    any of them
}