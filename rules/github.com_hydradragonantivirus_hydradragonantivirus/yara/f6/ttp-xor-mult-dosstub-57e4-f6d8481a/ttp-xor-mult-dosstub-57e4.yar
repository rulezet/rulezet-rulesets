rule TTP_XOR_MULT_DOSStub_57e4 {
  strings:
    $key_57e4 = { 03 8c [2] 77 94 [2] 30 96 [2] 77 87 [2] 39 8b [2] 35 81 [2] 22 8a [2] 39 c4 [2] 04 }

  condition:
    any of them
}