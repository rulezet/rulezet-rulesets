rule TTP_XOR_MULT_DOSStub_3326 {
  strings:
    $key_3326 = { 67 4e [2] 13 56 [2] 54 54 [2] 13 45 [2] 5d 49 [2] 51 43 [2] 46 48 [2] 5d 06 [2] 60 }

  condition:
    any of them
}