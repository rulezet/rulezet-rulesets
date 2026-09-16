rule TTP_XOR_MULT_DOSStub_34e4 {
  strings:
    $key_34e4 = { 60 8c [2] 14 94 [2] 53 96 [2] 14 87 [2] 5a 8b [2] 56 81 [2] 41 8a [2] 5a c4 [2] 67 }

  condition:
    any of them
}