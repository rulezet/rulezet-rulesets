rule TTP_XOR_MULT_DOSStub_4039 {
  strings:
    $key_4039 = { 14 51 [2] 60 49 [2] 27 4b [2] 60 5a [2] 2e 56 [2] 22 5c [2] 35 57 [2] 2e 19 [2] 13 }

  condition:
    any of them
}