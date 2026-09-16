rule TTP_XOR_MULT_DOSStub_5f73 {
  strings:
    $key_5f73 = { 0b 1b [2] 7f 03 [2] 38 01 [2] 7f 10 [2] 31 1c [2] 3d 16 [2] 2a 1d [2] 31 53 [2] 0c }

  condition:
    any of them
}