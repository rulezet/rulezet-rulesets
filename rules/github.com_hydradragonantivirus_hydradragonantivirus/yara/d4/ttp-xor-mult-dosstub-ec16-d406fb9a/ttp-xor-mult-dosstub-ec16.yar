rule TTP_XOR_MULT_DOSStub_ec16 {
  strings:
    $key_ec16 = { b8 7e [2] cc 66 [2] 8b 64 [2] cc 75 [2] 82 79 [2] 8e 73 [2] 99 78 [2] 82 36 [2] bf }

  condition:
    any of them
}