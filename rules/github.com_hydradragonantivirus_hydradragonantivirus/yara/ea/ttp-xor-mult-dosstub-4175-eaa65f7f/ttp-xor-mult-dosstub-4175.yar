rule TTP_XOR_MULT_DOSStub_4175 {
  strings:
    $key_4175 = { 15 1d [2] 61 05 [2] 26 07 [2] 61 16 [2] 2f 1a [2] 23 10 [2] 34 1b [2] 2f 55 [2] 12 }

  condition:
    any of them
}