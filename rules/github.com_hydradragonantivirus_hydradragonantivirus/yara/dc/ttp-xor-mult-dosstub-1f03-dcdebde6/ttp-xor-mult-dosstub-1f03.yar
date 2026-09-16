rule TTP_XOR_MULT_DOSStub_1f03 {
  strings:
    $key_1f03 = { 4b 6b [2] 3f 73 [2] 78 71 [2] 3f 60 [2] 71 6c [2] 7d 66 [2] 6a 6d [2] 71 23 [2] 4c }

  condition:
    any of them
}