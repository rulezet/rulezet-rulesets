rule TTP_XOR_MULT_DOSStub_7118 {
  strings:
    $key_7118 = { 25 70 [2] 51 68 [2] 16 6a [2] 51 7b [2] 1f 77 [2] 13 7d [2] 04 76 [2] 1f 38 [2] 22 }

  condition:
    any of them
}