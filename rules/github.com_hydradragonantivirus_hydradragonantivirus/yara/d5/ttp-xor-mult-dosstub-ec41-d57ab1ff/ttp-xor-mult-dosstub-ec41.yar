rule TTP_XOR_MULT_DOSStub_ec41 {
  strings:
    $key_ec41 = { b8 29 [2] cc 31 [2] 8b 33 [2] cc 22 [2] 82 2e [2] 8e 24 [2] 99 2f [2] 82 61 [2] bf }

  condition:
    any of them
}