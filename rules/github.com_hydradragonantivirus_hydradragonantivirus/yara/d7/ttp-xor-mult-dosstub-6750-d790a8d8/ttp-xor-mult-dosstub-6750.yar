rule TTP_XOR_MULT_DOSStub_6750 {
  strings:
    $key_6750 = { 33 38 [2] 47 20 [2] 00 22 [2] 47 33 [2] 09 3f [2] 05 35 [2] 12 3e [2] 09 70 [2] 34 }

  condition:
    any of them
}