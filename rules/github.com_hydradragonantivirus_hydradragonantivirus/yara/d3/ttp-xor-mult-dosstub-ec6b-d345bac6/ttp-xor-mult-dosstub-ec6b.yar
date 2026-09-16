rule TTP_XOR_MULT_DOSStub_ec6b {
  strings:
    $key_ec6b = { b8 03 [2] cc 1b [2] 8b 19 [2] cc 08 [2] 82 04 [2] 8e 0e [2] 99 05 [2] 82 4b [2] bf }

  condition:
    any of them
}