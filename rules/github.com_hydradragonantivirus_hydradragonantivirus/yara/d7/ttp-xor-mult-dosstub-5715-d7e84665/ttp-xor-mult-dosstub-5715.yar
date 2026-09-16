rule TTP_XOR_MULT_DOSStub_5715 {
  strings:
    $key_5715 = { 03 7d [2] 77 65 [2] 30 67 [2] 77 76 [2] 39 7a [2] 35 70 [2] 22 7b [2] 39 35 [2] 04 }

  condition:
    any of them
}