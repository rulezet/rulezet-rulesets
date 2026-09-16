rule TTP_XOR_MULT_DOSStub_5017 {
  strings:
    $key_5017 = { 04 7f [2] 70 67 [2] 37 65 [2] 70 74 [2] 3e 78 [2] 32 72 [2] 25 79 [2] 3e 37 [2] 03 }

  condition:
    any of them
}