rule TTP_XOR_MULT_DOSStub_24e6 {
  strings:
    $key_24e6 = { 70 8e [2] 04 96 [2] 43 94 [2] 04 85 [2] 4a 89 [2] 46 83 [2] 51 88 [2] 4a c6 [2] 77 }

  condition:
    any of them
}