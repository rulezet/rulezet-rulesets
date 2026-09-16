rule TTP_XOR_MULT_DOSStub_ec46 {
  strings:
    $key_ec46 = { b8 2e [2] cc 36 [2] 8b 34 [2] cc 25 [2] 82 29 [2] 8e 23 [2] 99 28 [2] 82 66 [2] bf }

  condition:
    any of them
}