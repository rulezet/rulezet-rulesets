rule TTP_XOR_MULT_DOSStub_71f5 {
  strings:
    $key_71f5 = { 25 9d [2] 51 85 [2] 16 87 [2] 51 96 [2] 1f 9a [2] 13 90 [2] 04 9b [2] 1f d5 [2] 22 }

  condition:
    any of them
}