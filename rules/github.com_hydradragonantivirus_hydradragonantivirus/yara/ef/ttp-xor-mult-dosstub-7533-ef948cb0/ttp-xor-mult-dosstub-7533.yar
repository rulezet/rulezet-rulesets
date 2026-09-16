rule TTP_XOR_MULT_DOSStub_7533 {
  strings:
    $key_7533 = { 21 5b [2] 55 43 [2] 12 41 [2] 55 50 [2] 1b 5c [2] 17 56 [2] 00 5d [2] 1b 13 [2] 26 }

  condition:
    any of them
}