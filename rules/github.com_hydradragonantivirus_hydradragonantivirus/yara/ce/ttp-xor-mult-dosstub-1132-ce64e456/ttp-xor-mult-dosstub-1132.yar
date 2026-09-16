rule TTP_XOR_MULT_DOSStub_1132 {
  strings:
    $key_1132 = { 45 5a [2] 31 42 [2] 76 40 [2] 31 51 [2] 7f 5d [2] 73 57 [2] 64 5c [2] 7f 12 [2] 42 }

  condition:
    any of them
}