rule TTP_XOR_MULT_DOSStub_7a29 {
  strings:
    $key_7a29 = { 2e 41 [2] 5a 59 [2] 1d 5b [2] 5a 4a [2] 14 46 [2] 18 4c [2] 0f 47 [2] 14 09 [2] 29 }

  condition:
    any of them
}