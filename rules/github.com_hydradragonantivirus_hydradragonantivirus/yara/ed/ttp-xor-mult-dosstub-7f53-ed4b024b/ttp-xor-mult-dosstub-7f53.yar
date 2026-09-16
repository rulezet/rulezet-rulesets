rule TTP_XOR_MULT_DOSStub_7f53 {
  strings:
    $key_7f53 = { 2b 3b [2] 5f 23 [2] 18 21 [2] 5f 30 [2] 11 3c [2] 1d 36 [2] 0a 3d [2] 11 73 [2] 2c }

  condition:
    any of them
}