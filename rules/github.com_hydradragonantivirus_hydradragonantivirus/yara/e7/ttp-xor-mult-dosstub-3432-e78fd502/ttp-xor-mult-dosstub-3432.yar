rule TTP_XOR_MULT_DOSStub_3432 {
  strings:
    $key_3432 = { 60 5a [2] 14 42 [2] 53 40 [2] 14 51 [2] 5a 5d [2] 56 57 [2] 41 5c [2] 5a 12 [2] 67 }

  condition:
    any of them
}