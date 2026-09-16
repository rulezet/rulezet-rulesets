rule TTP_XOR_MULT_DOSStub_6047 {
  strings:
    $key_6047 = { 34 2f [2] 40 37 [2] 07 35 [2] 40 24 [2] 0e 28 [2] 02 22 [2] 15 29 [2] 0e 67 [2] 33 }

  condition:
    any of them
}