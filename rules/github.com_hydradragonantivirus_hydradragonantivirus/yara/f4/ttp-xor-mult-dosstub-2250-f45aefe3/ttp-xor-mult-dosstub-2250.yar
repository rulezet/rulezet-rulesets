rule TTP_XOR_MULT_DOSStub_2250 {
  strings:
    $key_2250 = { 76 38 [2] 02 20 [2] 45 22 [2] 02 33 [2] 4c 3f [2] 40 35 [2] 57 3e [2] 4c 70 [2] 71 }

  condition:
    any of them
}