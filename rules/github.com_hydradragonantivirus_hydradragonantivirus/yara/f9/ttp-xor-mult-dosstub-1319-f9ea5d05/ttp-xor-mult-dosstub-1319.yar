rule TTP_XOR_MULT_DOSStub_1319 {
  strings:
    $key_1319 = { 47 71 [2] 33 69 [2] 74 6b [2] 33 7a [2] 7d 76 [2] 71 7c [2] 66 77 [2] 7d 39 [2] 40 }

  condition:
    any of them
}