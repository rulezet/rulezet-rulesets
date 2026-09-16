rule TTP_XOR_MULT_DOSStub_1733 {
  strings:
    $key_1733 = { 43 5b [2] 37 43 [2] 70 41 [2] 37 50 [2] 79 5c [2] 75 56 [2] 62 5d [2] 79 13 [2] 44 }

  condition:
    any of them
}