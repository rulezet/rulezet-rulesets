rule TTP_XOR_MULT_DOSStub_3518 {
  strings:
    $key_3518 = { 61 70 [2] 15 68 [2] 52 6a [2] 15 7b [2] 5b 77 [2] 57 7d [2] 40 76 [2] 5b 38 [2] 66 }

  condition:
    any of them
}