rule TTP_XOR_MULT_DOSStub_1632 {
  strings:
    $key_1632 = { 42 5a [2] 36 42 [2] 71 40 [2] 36 51 [2] 78 5d [2] 74 57 [2] 63 5c [2] 78 12 [2] 45 }

  condition:
    any of them
}