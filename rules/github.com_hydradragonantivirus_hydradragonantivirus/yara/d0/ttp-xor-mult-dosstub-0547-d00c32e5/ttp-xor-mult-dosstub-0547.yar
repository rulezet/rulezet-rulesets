rule TTP_XOR_MULT_DOSStub_0547 {
  strings:
    $key_0547 = { 51 2f [2] 25 37 [2] 62 35 [2] 25 24 [2] 6b 28 [2] 67 22 [2] 70 29 [2] 6b 67 [2] 56 }

  condition:
    any of them
}