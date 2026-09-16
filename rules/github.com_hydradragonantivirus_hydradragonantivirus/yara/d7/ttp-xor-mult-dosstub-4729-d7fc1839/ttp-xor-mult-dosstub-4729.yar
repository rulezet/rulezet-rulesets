rule TTP_XOR_MULT_DOSStub_4729 {
  strings:
    $key_4729 = { 13 41 [2] 67 59 [2] 20 5b [2] 67 4a [2] 29 46 [2] 25 4c [2] 32 47 [2] 29 09 [2] 14 }

  condition:
    any of them
}