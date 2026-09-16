rule TTP_XOR_MULT_DOSStub_6747 {
  strings:
    $key_6747 = { 33 2f [2] 47 37 [2] 00 35 [2] 47 24 [2] 09 28 [2] 05 22 [2] 12 29 [2] 09 67 [2] 34 }

  condition:
    any of them
}