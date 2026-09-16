rule TTP_XOR_MULT_DOSStub_4719 {
  strings:
    $key_4719 = { 13 71 [2] 67 69 [2] 20 6b [2] 67 7a [2] 29 76 [2] 25 7c [2] 32 77 [2] 29 39 [2] 14 }

  condition:
    any of them
}