rule TTP_XOR_MULT_DOSStub_7105 {
  strings:
    $key_7105 = { 25 6d [2] 51 75 [2] 16 77 [2] 51 66 [2] 1f 6a [2] 13 60 [2] 04 6b [2] 1f 25 [2] 22 }

  condition:
    any of them
}