rule TTP_XOR_MULT_DOSStub_1536 {
  strings:
    $key_1536 = { 41 5e [2] 35 46 [2] 72 44 [2] 35 55 [2] 7b 59 [2] 77 53 [2] 60 58 [2] 7b 16 [2] 46 }

  condition:
    any of them
}