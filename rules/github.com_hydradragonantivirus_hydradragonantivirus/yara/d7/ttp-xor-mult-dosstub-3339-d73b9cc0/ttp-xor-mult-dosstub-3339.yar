rule TTP_XOR_MULT_DOSStub_3339 {
  strings:
    $key_3339 = { 67 51 [2] 13 49 [2] 54 4b [2] 13 5a [2] 5d 56 [2] 51 5c [2] 46 57 [2] 5d 19 [2] 60 }

  condition:
    any of them
}