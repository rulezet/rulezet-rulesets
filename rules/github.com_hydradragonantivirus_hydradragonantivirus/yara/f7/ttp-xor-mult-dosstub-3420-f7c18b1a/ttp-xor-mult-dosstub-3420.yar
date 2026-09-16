rule TTP_XOR_MULT_DOSStub_3420 {
  strings:
    $key_3420 = { 60 48 [2] 14 50 [2] 53 52 [2] 14 43 [2] 5a 4f [2] 56 45 [2] 41 4e [2] 5a 00 [2] 67 }

  condition:
    any of them
}