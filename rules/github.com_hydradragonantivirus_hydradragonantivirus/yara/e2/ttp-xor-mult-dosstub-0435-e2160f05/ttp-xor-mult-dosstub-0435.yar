rule TTP_XOR_MULT_DOSStub_0435 {
  strings:
    $key_0435 = { 50 5d [2] 24 45 [2] 63 47 [2] 24 56 [2] 6a 5a [2] 66 50 [2] 71 5b [2] 6a 15 [2] 57 }

  condition:
    any of them
}