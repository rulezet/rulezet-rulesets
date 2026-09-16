rule TTP_XOR_MULT_DOSStub_6f75 {
  strings:
    $key_6f75 = { 3b 1d [2] 4f 05 [2] 08 07 [2] 4f 16 [2] 01 1a [2] 0d 10 [2] 1a 1b [2] 01 55 [2] 3c }

  condition:
    any of them
}