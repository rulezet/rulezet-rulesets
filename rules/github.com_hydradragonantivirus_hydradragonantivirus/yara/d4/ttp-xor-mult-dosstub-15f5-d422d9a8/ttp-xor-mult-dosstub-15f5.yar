rule TTP_XOR_MULT_DOSStub_15f5 {
  strings:
    $key_15f5 = { 41 9d [2] 35 85 [2] 72 87 [2] 35 96 [2] 7b 9a [2] 77 90 [2] 60 9b [2] 7b d5 [2] 46 }

  condition:
    any of them
}