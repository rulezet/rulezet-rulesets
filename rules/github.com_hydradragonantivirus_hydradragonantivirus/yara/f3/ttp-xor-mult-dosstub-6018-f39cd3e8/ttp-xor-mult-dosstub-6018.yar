rule TTP_XOR_MULT_DOSStub_6018 {
  strings:
    $key_6018 = { 34 70 [2] 40 68 [2] 07 6a [2] 40 7b [2] 0e 77 [2] 02 7d [2] 15 76 [2] 0e 38 [2] 33 }

  condition:
    any of them
}