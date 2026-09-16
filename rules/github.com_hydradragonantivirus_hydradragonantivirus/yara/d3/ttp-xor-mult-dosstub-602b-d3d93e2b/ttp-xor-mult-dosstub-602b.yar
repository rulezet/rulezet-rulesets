rule TTP_XOR_MULT_DOSStub_602b {
  strings:
    $key_602b = { 34 43 [2] 40 5b [2] 07 59 [2] 40 48 [2] 0e 44 [2] 02 4e [2] 15 45 [2] 0e 0b [2] 33 }

  condition:
    any of them
}