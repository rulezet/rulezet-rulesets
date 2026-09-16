rule TTP_XOR_MULT_DOSStub_0538 {
  strings:
    $key_0538 = { 51 50 [2] 25 48 [2] 62 4a [2] 25 5b [2] 6b 57 [2] 67 5d [2] 70 56 [2] 6b 18 [2] 56 }

  condition:
    any of them
}