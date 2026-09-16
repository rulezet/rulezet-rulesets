rule TTP_XOR_MULT_DOSStub_7a69 {
  strings:
    $key_7a69 = { 2e 01 [2] 5a 19 [2] 1d 1b [2] 5a 0a [2] 14 06 [2] 18 0c [2] 0f 07 [2] 14 49 [2] 29 }

  condition:
    any of them
}