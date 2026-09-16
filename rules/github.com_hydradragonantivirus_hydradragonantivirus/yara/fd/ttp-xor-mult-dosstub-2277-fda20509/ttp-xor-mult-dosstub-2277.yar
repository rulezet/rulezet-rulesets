rule TTP_XOR_MULT_DOSStub_2277 {
  strings:
    $key_2277 = { 76 1f [2] 02 07 [2] 45 05 [2] 02 14 [2] 4c 18 [2] 40 12 [2] 57 19 [2] 4c 57 [2] 71 }

  condition:
    any of them
}