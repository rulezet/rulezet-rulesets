rule TTP_XOR_MULT_DOSStub_ec20 {
  strings:
    $key_ec20 = { b8 48 [2] cc 50 [2] 8b 52 [2] cc 43 [2] 82 4f [2] 8e 45 [2] 99 4e [2] 82 00 [2] bf }

  condition:
    any of them
}