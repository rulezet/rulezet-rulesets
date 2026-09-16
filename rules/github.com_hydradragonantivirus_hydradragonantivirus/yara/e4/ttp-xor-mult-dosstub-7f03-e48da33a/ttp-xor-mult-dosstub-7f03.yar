rule TTP_XOR_MULT_DOSStub_7f03 {
  strings:
    $key_7f03 = { 2b 6b [2] 5f 73 [2] 18 71 [2] 5f 60 [2] 11 6c [2] 1d 66 [2] 0a 6d [2] 11 23 [2] 2c }

  condition:
    any of them
}