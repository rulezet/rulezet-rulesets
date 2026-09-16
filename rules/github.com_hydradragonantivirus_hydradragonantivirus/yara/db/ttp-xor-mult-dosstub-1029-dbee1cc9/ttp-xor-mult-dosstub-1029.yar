rule TTP_XOR_MULT_DOSStub_1029 {
  strings:
    $key_1029 = { 44 41 [2] 30 59 [2] 77 5b [2] 30 4a [2] 7e 46 [2] 72 4c [2] 65 47 [2] 7e 09 [2] 43 }

  condition:
    any of them
}