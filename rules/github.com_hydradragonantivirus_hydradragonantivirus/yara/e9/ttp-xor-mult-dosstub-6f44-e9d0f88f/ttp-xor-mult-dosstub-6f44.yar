rule TTP_XOR_MULT_DOSStub_6f44 {
  strings:
    $key_6f44 = { 3b 2c [2] 4f 34 [2] 08 36 [2] 4f 27 [2] 01 2b [2] 0d 21 [2] 1a 2a [2] 01 64 [2] 3c }

  condition:
    any of them
}