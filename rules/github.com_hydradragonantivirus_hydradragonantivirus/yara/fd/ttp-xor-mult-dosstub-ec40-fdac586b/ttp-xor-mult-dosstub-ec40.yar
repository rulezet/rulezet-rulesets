rule TTP_XOR_MULT_DOSStub_ec40 {
  strings:
    $key_ec40 = { b8 28 [2] cc 30 [2] 8b 32 [2] cc 23 [2] 82 2f [2] 8e 25 [2] 99 2e [2] 82 60 [2] bf }

  condition:
    any of them
}