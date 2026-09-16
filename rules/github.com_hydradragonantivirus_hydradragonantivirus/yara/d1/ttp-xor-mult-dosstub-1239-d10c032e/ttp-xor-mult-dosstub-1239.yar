rule TTP_XOR_MULT_DOSStub_1239 {
  strings:
    $key_1239 = { 46 51 [2] 32 49 [2] 75 4b [2] 32 5a [2] 7c 56 [2] 70 5c [2] 67 57 [2] 7c 19 [2] 41 }

  condition:
    any of them
}