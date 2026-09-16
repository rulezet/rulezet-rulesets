rule TTP_XOR_MULT_DOSStub_7a64 {
  strings:
    $key_7a64 = { 2e 0c [2] 5a 14 [2] 1d 16 [2] 5a 07 [2] 14 0b [2] 18 01 [2] 0f 0a [2] 14 44 [2] 29 }

  condition:
    any of them
}