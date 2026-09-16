rule TTP_XOR_MULT_DOSStub_5f43 {
  strings:
    $key_5f43 = { 0b 2b [2] 7f 33 [2] 38 31 [2] 7f 20 [2] 31 2c [2] 3d 26 [2] 2a 2d [2] 31 63 [2] 0c }

  condition:
    any of them
}