rule TTP_XOR_MULT_DOSStub_1775 {
  strings:
    $key_1775 = { 43 1d [2] 37 05 [2] 70 07 [2] 37 16 [2] 79 1a [2] 75 10 [2] 62 1b [2] 79 55 [2] 44 }

  condition:
    any of them
}