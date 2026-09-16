rule TTP_XOR_MULT_DOSStub_5020 {
  strings:
    $key_5020 = { 04 48 [2] 70 50 [2] 37 52 [2] 70 43 [2] 3e 4f [2] 32 45 [2] 25 4e [2] 3e 00 [2] 03 }

  condition:
    any of them
}