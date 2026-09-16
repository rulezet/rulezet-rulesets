rule TTP_XOR_MULT_DOSStub_3619 {
  strings:
    $key_3619 = { 62 71 [2] 16 69 [2] 51 6b [2] 16 7a [2] 58 76 [2] 54 7c [2] 43 77 [2] 58 39 [2] 65 }

  condition:
    any of them
}