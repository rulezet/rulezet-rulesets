rule TTP_XOR_MULT_DOSStub_235b {
  strings:
    $key_235b = { 77 33 [2] 03 2b [2] 44 29 [2] 03 38 [2] 4d 34 [2] 41 3e [2] 56 35 [2] 4d 7b [2] 70 }

  condition:
    any of them
}