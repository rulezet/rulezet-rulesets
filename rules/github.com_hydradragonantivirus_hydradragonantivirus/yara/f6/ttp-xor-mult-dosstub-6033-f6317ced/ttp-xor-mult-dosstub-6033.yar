rule TTP_XOR_MULT_DOSStub_6033 {
  strings:
    $key_6033 = { 34 5b [2] 40 43 [2] 07 41 [2] 40 50 [2] 0e 5c [2] 02 56 [2] 15 5d [2] 0e 13 [2] 33 }

  condition:
    any of them
}