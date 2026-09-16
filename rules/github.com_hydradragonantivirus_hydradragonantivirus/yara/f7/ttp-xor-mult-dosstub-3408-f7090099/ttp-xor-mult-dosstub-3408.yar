rule TTP_XOR_MULT_DOSStub_3408 {
  strings:
    $key_3408 = { 60 60 [2] 14 78 [2] 53 7a [2] 14 6b [2] 5a 67 [2] 56 6d [2] 41 66 [2] 5a 28 [2] 67 }

  condition:
    any of them
}