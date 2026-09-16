rule TTP_XOR_MULT_DOSStub_7236 {
  strings:
    $key_7236 = { 26 5e [2] 52 46 [2] 15 44 [2] 52 55 [2] 1c 59 [2] 10 53 [2] 07 58 [2] 1c 16 [2] 21 }

  condition:
    any of them
}