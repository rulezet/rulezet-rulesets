rule TTP_XOR_MULT_DOSStub_2133 {
  strings:
    $key_2133 = { 75 5b [2] 01 43 [2] 46 41 [2] 01 50 [2] 4f 5c [2] 43 56 [2] 54 5d [2] 4f 13 [2] 72 }

  condition:
    any of them
}