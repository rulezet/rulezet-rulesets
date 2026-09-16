rule TTP_XOR_MULT_DOSStub_0159 {
  strings:
    $key_0159 = { 55 31 [2] 21 29 [2] 66 2b [2] 21 3a [2] 6f 36 [2] 63 3c [2] 74 37 [2] 6f 79 [2] 52 }

  condition:
    any of them
}