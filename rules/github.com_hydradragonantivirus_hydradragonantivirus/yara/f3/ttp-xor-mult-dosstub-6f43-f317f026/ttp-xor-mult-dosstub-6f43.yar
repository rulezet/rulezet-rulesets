rule TTP_XOR_MULT_DOSStub_6f43 {
  strings:
    $key_6f43 = { 3b 2b [2] 4f 33 [2] 08 31 [2] 4f 20 [2] 01 2c [2] 0d 26 [2] 1a 2d [2] 01 63 [2] 3c }

  condition:
    any of them
}