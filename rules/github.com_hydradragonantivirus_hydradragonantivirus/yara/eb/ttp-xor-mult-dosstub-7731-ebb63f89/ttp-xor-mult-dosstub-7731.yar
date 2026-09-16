rule TTP_XOR_MULT_DOSStub_7731 {
  strings:
    $key_7731 = { 23 59 [2] 57 41 [2] 10 43 [2] 57 52 [2] 19 5e [2] 15 54 [2] 02 5f [2] 19 11 [2] 24 }

  condition:
    any of them
}