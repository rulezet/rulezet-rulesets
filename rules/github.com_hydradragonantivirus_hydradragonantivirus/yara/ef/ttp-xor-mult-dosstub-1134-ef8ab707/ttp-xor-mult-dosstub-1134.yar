rule TTP_XOR_MULT_DOSStub_1134 {
  strings:
    $key_1134 = { 45 5c [2] 31 44 [2] 76 46 [2] 31 57 [2] 7f 5b [2] 73 51 [2] 64 5a [2] 7f 14 [2] 42 }

  condition:
    any of them
}