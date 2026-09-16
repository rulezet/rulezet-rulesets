rule TTP_XOR_MULT_DOSStub_7329 {
  strings:
    $key_7329 = { 27 41 [2] 53 59 [2] 14 5b [2] 53 4a [2] 1d 46 [2] 11 4c [2] 06 47 [2] 1d 09 [2] 20 }

  condition:
    any of them
}