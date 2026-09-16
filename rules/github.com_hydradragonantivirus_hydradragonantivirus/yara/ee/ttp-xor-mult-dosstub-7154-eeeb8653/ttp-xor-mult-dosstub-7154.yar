rule TTP_XOR_MULT_DOSStub_7154 {
  strings:
    $key_7154 = { 25 3c [2] 51 24 [2] 16 26 [2] 51 37 [2] 1f 3b [2] 13 31 [2] 04 3a [2] 1f 74 [2] 22 }

  condition:
    any of them
}