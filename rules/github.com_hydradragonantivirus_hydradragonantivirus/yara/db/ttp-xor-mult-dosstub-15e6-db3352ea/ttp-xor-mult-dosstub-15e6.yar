rule TTP_XOR_MULT_DOSStub_15e6 {
  strings:
    $key_15e6 = { 41 8e [2] 35 96 [2] 72 94 [2] 35 85 [2] 7b 89 [2] 77 83 [2] 60 88 [2] 7b c6 [2] 46 }

  condition:
    any of them
}