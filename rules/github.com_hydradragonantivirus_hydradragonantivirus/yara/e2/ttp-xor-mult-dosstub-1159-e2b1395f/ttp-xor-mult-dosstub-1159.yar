rule TTP_XOR_MULT_DOSStub_1159 {
  strings:
    $key_1159 = { 45 31 [2] 31 29 [2] 76 2b [2] 31 3a [2] 7f 36 [2] 73 3c [2] 64 37 [2] 7f 79 [2] 42 }

  condition:
    any of them
}