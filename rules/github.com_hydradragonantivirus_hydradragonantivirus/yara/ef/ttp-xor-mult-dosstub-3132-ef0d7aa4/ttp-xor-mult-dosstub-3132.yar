rule TTP_XOR_MULT_DOSStub_3132 {
  strings:
    $key_3132 = { 65 5a [2] 11 42 [2] 56 40 [2] 11 51 [2] 5f 5d [2] 53 57 [2] 44 5c [2] 5f 12 [2] 62 }

  condition:
    any of them
}