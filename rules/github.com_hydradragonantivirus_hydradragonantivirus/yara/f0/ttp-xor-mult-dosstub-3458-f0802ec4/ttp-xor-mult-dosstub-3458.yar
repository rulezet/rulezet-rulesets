rule TTP_XOR_MULT_DOSStub_3458 {
  strings:
    $key_3458 = { 60 30 [2] 14 28 [2] 53 2a [2] 14 3b [2] 5a 37 [2] 56 3d [2] 41 36 [2] 5a 78 [2] 67 }

  condition:
    any of them
}