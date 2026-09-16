rule TTP_XOR_MULT_DOSStub_6350 {
  strings:
    $key_6350 = { 37 38 [2] 43 20 [2] 04 22 [2] 43 33 [2] 0d 3f [2] 01 35 [2] 16 3e [2] 0d 70 [2] 30 }

  condition:
    any of them
}