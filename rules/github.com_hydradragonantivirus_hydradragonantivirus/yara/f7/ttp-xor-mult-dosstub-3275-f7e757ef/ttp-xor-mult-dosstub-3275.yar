rule TTP_XOR_MULT_DOSStub_3275 {
  strings:
    $key_3275 = { 66 1d [2] 12 05 [2] 55 07 [2] 12 16 [2] 5c 1a [2] 50 10 [2] 47 1b [2] 5c 55 [2] 61 }

  condition:
    any of them
}