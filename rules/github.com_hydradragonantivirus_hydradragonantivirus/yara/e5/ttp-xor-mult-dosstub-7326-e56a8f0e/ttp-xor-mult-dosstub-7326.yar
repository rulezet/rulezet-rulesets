rule TTP_XOR_MULT_DOSStub_7326 {
  strings:
    $key_7326 = { 27 4e [2] 53 56 [2] 14 54 [2] 53 45 [2] 1d 49 [2] 11 43 [2] 06 48 [2] 1d 06 [2] 20 }

  condition:
    any of them
}