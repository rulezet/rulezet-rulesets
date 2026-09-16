rule TTP_XOR_MULT_DOSStub_6f78 {
  strings:
    $key_6f78 = { 3b 10 [2] 4f 08 [2] 08 0a [2] 4f 1b [2] 01 17 [2] 0d 1d [2] 1a 16 [2] 01 58 [2] 3c }

  condition:
    any of them
}