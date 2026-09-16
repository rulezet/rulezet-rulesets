rule TTP_XOR_MULT_DOSStub_5619 {
  strings:
    $key_5619 = { 02 71 [2] 76 69 [2] 31 6b [2] 76 7a [2] 38 76 [2] 34 7c [2] 23 77 [2] 38 39 [2] 05 }

  condition:
    any of them
}