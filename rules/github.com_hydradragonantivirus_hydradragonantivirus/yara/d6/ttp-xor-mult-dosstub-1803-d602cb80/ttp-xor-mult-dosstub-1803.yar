rule TTP_XOR_MULT_DOSStub_1803 {
  strings:
    $key_1803 = { 4c 6b [2] 38 73 [2] 7f 71 [2] 38 60 [2] 76 6c [2] 7a 66 [2] 6d 6d [2] 76 23 [2] 4b }

  condition:
    any of them
}