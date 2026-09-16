rule TTP_XOR_MULT_DOSStub_1521 {
  strings:
    $key_1521 = { 41 49 [2] 35 51 [2] 72 53 [2] 35 42 [2] 7b 4e [2] 77 44 [2] 60 4f [2] 7b 01 [2] 46 }

  condition:
    any of them
}