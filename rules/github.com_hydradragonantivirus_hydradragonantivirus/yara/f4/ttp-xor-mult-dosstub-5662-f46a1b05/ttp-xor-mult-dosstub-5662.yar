rule TTP_XOR_MULT_DOSStub_5662 {
  strings:
    $key_5662 = { 02 0a [2] 76 12 [2] 31 10 [2] 76 01 [2] 38 0d [2] 34 07 [2] 23 0c [2] 38 42 [2] 05 }

  condition:
    any of them
}