rule TTP_XOR_MULT_DOSStub_7159 {
  strings:
    $key_7159 = { 25 31 [2] 51 29 [2] 16 2b [2] 51 3a [2] 1f 36 [2] 13 3c [2] 04 37 [2] 1f 79 [2] 22 }

  condition:
    any of them
}