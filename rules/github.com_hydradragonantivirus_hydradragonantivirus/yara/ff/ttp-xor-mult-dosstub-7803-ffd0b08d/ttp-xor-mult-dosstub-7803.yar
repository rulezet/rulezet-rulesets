rule TTP_XOR_MULT_DOSStub_7803 {
  strings:
    $key_7803 = { 2c 6b [2] 58 73 [2] 1f 71 [2] 58 60 [2] 16 6c [2] 1a 66 [2] 0d 6d [2] 16 23 [2] 2b }

  condition:
    any of them
}