rule TTP_XOR_MULT_DOSStub_7421 {
  strings:
    $key_7421 = { 20 49 [2] 54 51 [2] 13 53 [2] 54 42 [2] 1a 4e [2] 16 44 [2] 01 4f [2] 1a 01 [2] 27 }

  condition:
    any of them
}