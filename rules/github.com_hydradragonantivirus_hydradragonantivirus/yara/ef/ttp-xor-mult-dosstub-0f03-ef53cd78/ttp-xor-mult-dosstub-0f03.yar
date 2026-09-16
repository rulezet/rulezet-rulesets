rule TTP_XOR_MULT_DOSStub_0f03 {
  strings:
    $key_0f03 = { 5b 6b [2] 2f 73 [2] 68 71 [2] 2f 60 [2] 61 6c [2] 6d 66 [2] 7a 6d [2] 61 23 [2] 5c }

  condition:
    any of them
}