rule TTP_XOR_MULT_DOSStub_1214 {
  strings:
    $key_1214 = { 46 7c [2] 32 64 [2] 75 66 [2] 32 77 [2] 7c 7b [2] 70 71 [2] 67 7a [2] 7c 34 [2] 41 }

  condition:
    any of them
}