rule TTP_XOR_MULT_DOSStub_6460 {
  strings:
    $key_6460 = { 30 08 [2] 44 10 [2] 03 12 [2] 44 03 [2] 0a 0f [2] 06 05 [2] 11 0e [2] 0a 40 [2] 37 }

  condition:
    any of them
}