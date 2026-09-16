rule TTP_XOR_MULT_DOSStub_5650 {
  strings:
    $key_5650 = { 02 38 [2] 76 20 [2] 31 22 [2] 76 33 [2] 38 3f [2] 34 35 [2] 23 3e [2] 38 70 [2] 05 }

  condition:
    any of them
}