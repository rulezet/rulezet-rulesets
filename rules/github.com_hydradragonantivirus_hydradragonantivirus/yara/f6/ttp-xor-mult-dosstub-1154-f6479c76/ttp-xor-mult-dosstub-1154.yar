rule TTP_XOR_MULT_DOSStub_1154 {
  strings:
    $key_1154 = { 45 3c [2] 31 24 [2] 76 26 [2] 31 37 [2] 7f 3b [2] 73 31 [2] 64 3a [2] 7f 74 [2] 42 }

  condition:
    any of them
}