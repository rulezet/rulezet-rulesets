rule TTP_XOR_MULT_DOSStub_2414 {
  strings:
    $key_2414 = { 70 7c [2] 04 64 [2] 43 66 [2] 04 77 [2] 4a 7b [2] 46 71 [2] 51 7a [2] 4a 34 [2] 77 }

  condition:
    any of them
}