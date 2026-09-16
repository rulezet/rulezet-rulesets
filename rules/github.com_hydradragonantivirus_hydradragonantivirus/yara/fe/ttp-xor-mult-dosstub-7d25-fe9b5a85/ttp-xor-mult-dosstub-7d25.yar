rule TTP_XOR_MULT_DOSStub_7d25 {
  strings:
    $key_7d25 = { 29 4d [2] 5d 55 [2] 1a 57 [2] 5d 46 [2] 13 4a [2] 1f 40 [2] 08 4b [2] 13 05 [2] 2e }

  condition:
    any of them
}