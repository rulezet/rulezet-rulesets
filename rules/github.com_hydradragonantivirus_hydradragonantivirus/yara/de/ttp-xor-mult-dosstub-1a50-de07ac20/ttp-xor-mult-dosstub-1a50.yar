rule TTP_XOR_MULT_DOSStub_1a50 {
  strings:
    $key_1a50 = { 4e 38 [2] 3a 20 [2] 7d 22 [2] 3a 33 [2] 74 3f [2] 78 35 [2] 6f 3e [2] 74 70 [2] 49 }

  condition:
    any of them
}