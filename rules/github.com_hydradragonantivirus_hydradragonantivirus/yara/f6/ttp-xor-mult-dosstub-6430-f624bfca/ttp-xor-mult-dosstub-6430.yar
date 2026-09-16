rule TTP_XOR_MULT_DOSStub_6430 {
  strings:
    $key_6430 = { 30 58 [2] 44 40 [2] 03 42 [2] 44 53 [2] 0a 5f [2] 06 55 [2] 11 5e [2] 0a 10 [2] 37 }

  condition:
    any of them
}