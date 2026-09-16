rule TTP_XOR_MULT_DOSStub_ec06 {
  strings:
    $key_ec06 = { b8 6e [2] cc 76 [2] 8b 74 [2] cc 65 [2] 82 69 [2] 8e 63 [2] 99 68 [2] 82 26 [2] bf }

  condition:
    any of them
}