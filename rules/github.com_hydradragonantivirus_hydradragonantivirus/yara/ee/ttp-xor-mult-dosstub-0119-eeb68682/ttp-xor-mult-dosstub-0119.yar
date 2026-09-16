rule TTP_XOR_MULT_DOSStub_0119 {
  strings:
    $key_0119 = { 55 71 [2] 21 69 [2] 66 6b [2] 21 7a [2] 6f 76 [2] 63 7c [2] 74 77 [2] 6f 39 [2] 52 }

  condition:
    any of them
}