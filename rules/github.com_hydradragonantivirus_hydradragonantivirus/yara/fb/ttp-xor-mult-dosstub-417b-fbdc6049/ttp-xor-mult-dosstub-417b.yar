rule TTP_XOR_MULT_DOSStub_417b {
  strings:
    $key_417b = { 15 13 [2] 61 0b [2] 26 09 [2] 61 18 [2] 2f 14 [2] 23 1e [2] 34 15 [2] 2f 5b [2] 12 }

  condition:
    any of them
}