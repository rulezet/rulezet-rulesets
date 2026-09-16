rule TTP_XOR_MULT_DOSStub_2627 {
  strings:
    $key_2627 = { 72 4f [2] 06 57 [2] 41 55 [2] 06 44 [2] 48 48 [2] 44 42 [2] 53 49 [2] 48 07 [2] 75 }

  condition:
    any of them
}