rule TTP_XOR_MULT_DOSStub_1326 {
  strings:
    $key_1326 = { 47 4e [2] 33 56 [2] 74 54 [2] 33 45 [2] 7d 49 [2] 71 43 [2] 66 48 [2] 7d 06 [2] 40 }

  condition:
    any of them
}