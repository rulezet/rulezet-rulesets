rule TTP_XOR_MULT_DOSStub_2621 {
  strings:
    $key_2621 = { 72 49 [2] 06 51 [2] 41 53 [2] 06 42 [2] 48 4e [2] 44 44 [2] 53 4f [2] 48 01 [2] 75 }

  condition:
    any of them
}