rule TTP_XOR_MULT_DOSStub_3350 {
  strings:
    $key_3350 = { 67 38 [2] 13 20 [2] 54 22 [2] 13 33 [2] 5d 3f [2] 51 35 [2] 46 3e [2] 5d 70 [2] 60 }

  condition:
    any of them
}