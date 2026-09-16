rule TTP_XOR_MULT_DOSStub_4173 {
  strings:
    $key_4173 = { 15 1b [2] 61 03 [2] 26 01 [2] 61 10 [2] 2f 1c [2] 23 16 [2] 34 1d [2] 2f 53 [2] 12 }

  condition:
    any of them
}