rule TTP_XOR_MULT_DOSStub_766b {
  strings:
    $key_766b = { 22 03 [2] 56 1b [2] 11 19 [2] 56 08 [2] 18 04 [2] 14 0e [2] 03 05 [2] 18 4b [2] 25 }

  condition:
    any of them
}