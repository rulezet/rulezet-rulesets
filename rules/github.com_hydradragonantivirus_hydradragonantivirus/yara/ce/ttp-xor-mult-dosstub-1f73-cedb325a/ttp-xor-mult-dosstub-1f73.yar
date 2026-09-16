rule TTP_XOR_MULT_DOSStub_1f73 {
  strings:
    $key_1f73 = { 4b 1b [2] 3f 03 [2] 78 01 [2] 3f 10 [2] 71 1c [2] 7d 16 [2] 6a 1d [2] 71 53 [2] 4c }

  condition:
    any of them
}