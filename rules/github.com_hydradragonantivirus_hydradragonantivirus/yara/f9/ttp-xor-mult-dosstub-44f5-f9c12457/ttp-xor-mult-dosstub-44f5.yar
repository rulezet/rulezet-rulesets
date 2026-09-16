rule TTP_XOR_MULT_DOSStub_44f5 {
  strings:
    $key_44f5 = { 10 9d [2] 64 85 [2] 23 87 [2] 64 96 [2] 2a 9a [2] 26 90 [2] 31 9b [2] 2a d5 [2] 17 }

  condition:
    any of them
}