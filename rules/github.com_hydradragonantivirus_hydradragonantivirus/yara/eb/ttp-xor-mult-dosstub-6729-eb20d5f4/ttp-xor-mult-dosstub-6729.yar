rule TTP_XOR_MULT_DOSStub_6729 {
  strings:
    $key_6729 = { 33 41 [2] 47 59 [2] 00 5b [2] 47 4a [2] 09 46 [2] 05 4c [2] 12 47 [2] 09 09 [2] 34 }

  condition:
    any of them
}