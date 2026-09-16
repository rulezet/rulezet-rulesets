rule TTP_XOR_MULT_DOSStub_6436 {
  strings:
    $key_6436 = { 30 5e [2] 44 46 [2] 03 44 [2] 44 55 [2] 0a 59 [2] 06 53 [2] 11 58 [2] 0a 16 [2] 37 }

  condition:
    any of them
}