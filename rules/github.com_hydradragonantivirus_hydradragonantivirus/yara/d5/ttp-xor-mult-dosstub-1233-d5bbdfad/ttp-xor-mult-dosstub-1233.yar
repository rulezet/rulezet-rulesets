rule TTP_XOR_MULT_DOSStub_1233 {
  strings:
    $key_1233 = { 46 5b [2] 32 43 [2] 75 41 [2] 32 50 [2] 7c 5c [2] 70 56 [2] 67 5d [2] 7c 13 [2] 41 }

  condition:
    any of them
}