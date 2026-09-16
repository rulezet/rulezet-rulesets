rule TTP_XOR_MULT_DOSStub_6457 {
  strings:
    $key_6457 = { 30 3f [2] 44 27 [2] 03 25 [2] 44 34 [2] 0a 38 [2] 06 32 [2] 11 39 [2] 0a 77 [2] 37 }

  condition:
    any of them
}