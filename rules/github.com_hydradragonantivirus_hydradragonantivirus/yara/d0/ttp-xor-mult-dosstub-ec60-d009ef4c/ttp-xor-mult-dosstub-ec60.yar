rule TTP_XOR_MULT_DOSStub_ec60 {
  strings:
    $key_ec60 = { b8 08 [2] cc 10 [2] 8b 12 [2] cc 03 [2] 82 0f [2] 8e 05 [2] 99 0e [2] 82 40 [2] bf }

  condition:
    any of them
}