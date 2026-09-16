rule TTP_XOR_MULT_DOSStub_5d03 {
  strings:
    $key_5d03 = { 09 6b [2] 7d 73 [2] 3a 71 [2] 7d 60 [2] 33 6c [2] 3f 66 [2] 28 6d [2] 33 23 [2] 0e }

  condition:
    any of them
}