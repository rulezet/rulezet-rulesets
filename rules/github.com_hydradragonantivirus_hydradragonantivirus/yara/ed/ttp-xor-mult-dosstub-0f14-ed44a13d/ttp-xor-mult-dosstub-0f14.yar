rule TTP_XOR_MULT_DOSStub_0f14 {
  strings:
    $key_0f14 = { 5b 7c [2] 2f 64 [2] 68 66 [2] 2f 77 [2] 61 7b [2] 6d 71 [2] 7a 7a [2] 61 34 [2] 5c }

  condition:
    any of them
}