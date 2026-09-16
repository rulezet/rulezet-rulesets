rule TTP_XOR_MULT_DOSStub_7a79 {
  strings:
    $key_7a79 = { 2e 11 [2] 5a 09 [2] 1d 0b [2] 5a 1a [2] 14 16 [2] 18 1c [2] 0f 17 [2] 14 59 [2] 29 }

  condition:
    any of them
}