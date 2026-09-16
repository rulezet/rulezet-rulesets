rule TTP_XOR_MULT_DOSStub_3159 {
  strings:
    $key_3159 = { 65 31 [2] 11 29 [2] 56 2b [2] 11 3a [2] 5f 36 [2] 53 3c [2] 44 37 [2] 5f 79 [2] 62 }

  condition:
    any of them
}