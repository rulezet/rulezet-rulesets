rule TTP_XOR_MULT_DOSStub_7457 {
  strings:
    $key_7457 = { 20 3f [2] 54 27 [2] 13 25 [2] 54 34 [2] 1a 38 [2] 16 32 [2] 01 39 [2] 1a 77 [2] 27 }

  condition:
    any of them
}