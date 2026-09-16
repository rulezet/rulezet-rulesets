rule TTP_XOR_MULT_DOSStub_4020 {
  strings:
    $key_4020 = { 14 48 [2] 60 50 [2] 27 52 [2] 60 43 [2] 2e 4f [2] 22 45 [2] 35 4e [2] 2e 00 [2] 13 }

  condition:
    any of them
}