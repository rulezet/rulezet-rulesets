rule TTP_XOR_MULT_DOSStub_3330 {
  strings:
    $key_3330 = { 67 58 [2] 13 40 [2] 54 42 [2] 13 53 [2] 5d 5f [2] 51 55 [2] 46 5e [2] 5d 10 [2] 60 }

  condition:
    any of them
}