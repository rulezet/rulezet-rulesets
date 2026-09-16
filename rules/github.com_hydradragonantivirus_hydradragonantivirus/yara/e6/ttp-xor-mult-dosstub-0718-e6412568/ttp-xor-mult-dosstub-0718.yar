rule TTP_XOR_MULT_DOSStub_0718 {
  strings:
    $key_0718 = { 53 70 [2] 27 68 [2] 60 6a [2] 27 7b [2] 69 77 [2] 65 7d [2] 72 76 [2] 69 38 [2] 54 }

  condition:
    any of them
}