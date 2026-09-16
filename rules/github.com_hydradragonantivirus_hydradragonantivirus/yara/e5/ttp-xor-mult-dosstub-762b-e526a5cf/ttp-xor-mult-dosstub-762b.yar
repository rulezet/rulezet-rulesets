rule TTP_XOR_MULT_DOSStub_762b {
  strings:
    $key_762b = { 22 43 [2] 56 5b [2] 11 59 [2] 56 48 [2] 18 44 [2] 14 4e [2] 03 45 [2] 18 0b [2] 25 }

  condition:
    any of them
}