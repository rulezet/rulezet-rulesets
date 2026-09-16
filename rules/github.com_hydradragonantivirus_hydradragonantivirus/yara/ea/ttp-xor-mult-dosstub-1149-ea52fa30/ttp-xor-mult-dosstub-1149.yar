rule TTP_XOR_MULT_DOSStub_1149 {
  strings:
    $key_1149 = { 45 21 [2] 31 39 [2] 76 3b [2] 31 2a [2] 7f 26 [2] 73 2c [2] 64 27 [2] 7f 69 [2] 42 }

  condition:
    any of them
}