rule TTP_XOR_MULT_DOSStub_1614 {
  strings:
    $key_1614 = { 42 7c [2] 36 64 [2] 71 66 [2] 36 77 [2] 78 7b [2] 74 71 [2] 63 7a [2] 78 34 [2] 45 }

  condition:
    any of them
}