rule TTP_XOR_MULT_DOSStub_2619 {
  strings:
    $key_2619 = { 72 71 [2] 06 69 [2] 41 6b [2] 06 7a [2] 48 76 [2] 44 7c [2] 53 77 [2] 48 39 [2] 75 }

  condition:
    any of them
}