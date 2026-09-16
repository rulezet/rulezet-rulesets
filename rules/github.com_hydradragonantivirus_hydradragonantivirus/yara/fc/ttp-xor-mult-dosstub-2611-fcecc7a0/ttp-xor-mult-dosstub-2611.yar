rule TTP_XOR_MULT_DOSStub_2611 {
  strings:
    $key_2611 = { 72 79 [2] 06 61 [2] 41 63 [2] 06 72 [2] 48 7e [2] 44 74 [2] 53 7f [2] 48 31 [2] 75 }

  condition:
    any of them
}