rule TTP_XOR_MULT_DOSStub_2626 {
  strings:
    $key_2626 = { 72 4e [2] 06 56 [2] 41 54 [2] 06 45 [2] 48 49 [2] 44 43 [2] 53 48 [2] 48 06 [2] 75 }

  condition:
    any of them
}