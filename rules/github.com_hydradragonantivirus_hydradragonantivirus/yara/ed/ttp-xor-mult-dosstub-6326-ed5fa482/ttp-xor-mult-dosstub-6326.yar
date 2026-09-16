rule TTP_XOR_MULT_DOSStub_6326 {
  strings:
    $key_6326 = { 37 4e [2] 43 56 [2] 04 54 [2] 43 45 [2] 0d 49 [2] 01 43 [2] 16 48 [2] 0d 06 [2] 30 }

  condition:
    any of them
}