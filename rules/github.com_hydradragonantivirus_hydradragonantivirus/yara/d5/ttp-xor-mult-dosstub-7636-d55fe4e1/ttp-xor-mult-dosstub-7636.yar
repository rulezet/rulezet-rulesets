rule TTP_XOR_MULT_DOSStub_7636 {
  strings:
    $key_7636 = { 22 5e [2] 56 46 [2] 11 44 [2] 56 55 [2] 18 59 [2] 14 53 [2] 03 58 [2] 18 16 [2] 25 }

  condition:
    any of them
}