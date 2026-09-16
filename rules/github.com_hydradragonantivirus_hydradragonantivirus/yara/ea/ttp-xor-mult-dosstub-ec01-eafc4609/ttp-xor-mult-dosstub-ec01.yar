rule TTP_XOR_MULT_DOSStub_ec01 {
  strings:
    $key_ec01 = { b8 69 [2] cc 71 [2] 8b 73 [2] cc 62 [2] 82 6e [2] 8e 64 [2] 99 6f [2] 82 21 [2] bf }

  condition:
    any of them
}