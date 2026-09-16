rule TTP_XOR_MULT_DOSStub_1528 {
  strings:
    $key_1528 = { 41 40 [2] 35 58 [2] 72 5a [2] 35 4b [2] 7b 47 [2] 77 4d [2] 60 46 [2] 7b 08 [2] 46 }

  condition:
    any of them
}