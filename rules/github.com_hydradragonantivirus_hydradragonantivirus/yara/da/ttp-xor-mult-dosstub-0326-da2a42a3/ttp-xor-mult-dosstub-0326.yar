rule TTP_XOR_MULT_DOSStub_0326 {
  strings:
    $key_0326 = { 57 4e [2] 23 56 [2] 64 54 [2] 23 45 [2] 6d 49 [2] 61 43 [2] 76 48 [2] 6d 06 [2] 50 }

  condition:
    any of them
}