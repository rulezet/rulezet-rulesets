rule TTP_XOR_MULT_DOSStub_2608 {
  strings:
    $key_2608 = { 72 60 [2] 06 78 [2] 41 7a [2] 06 6b [2] 48 67 [2] 44 6d [2] 53 66 [2] 48 28 [2] 75 }

  condition:
    any of them
}