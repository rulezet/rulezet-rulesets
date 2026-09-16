rule TTP_XOR_MULT_DOSStub_5621 {
  strings:
    $key_5621 = { 02 49 [2] 76 51 [2] 31 53 [2] 76 42 [2] 38 4e [2] 34 44 [2] 23 4f [2] 38 01 [2] 05 }

  condition:
    any of them
}