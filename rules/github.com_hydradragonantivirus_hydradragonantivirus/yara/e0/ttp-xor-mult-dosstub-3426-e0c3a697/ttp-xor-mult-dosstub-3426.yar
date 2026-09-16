rule TTP_XOR_MULT_DOSStub_3426 {
  strings:
    $key_3426 = { 60 4e [2] 14 56 [2] 53 54 [2] 14 45 [2] 5a 49 [2] 56 43 [2] 41 48 [2] 5a 06 [2] 67 }

  condition:
    any of them
}