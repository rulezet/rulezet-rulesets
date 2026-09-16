rule TTP_XOR_MULT_DOSStub_3338 {
  strings:
    $key_3338 = { 67 50 [2] 13 48 [2] 54 4a [2] 13 5b [2] 5d 57 [2] 51 5d [2] 46 56 [2] 5d 18 [2] 60 }

  condition:
    any of them
}