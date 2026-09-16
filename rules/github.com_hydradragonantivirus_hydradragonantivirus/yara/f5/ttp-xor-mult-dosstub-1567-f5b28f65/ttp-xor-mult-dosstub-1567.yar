rule TTP_XOR_MULT_DOSStub_1567 {
  strings:
    $key_1567 = { 41 0f [2] 35 17 [2] 72 15 [2] 35 04 [2] 7b 08 [2] 77 02 [2] 60 09 [2] 7b 47 [2] 46 }

  condition:
    any of them
}