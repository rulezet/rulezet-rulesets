rule TTP_XOR_MULT_DOSStub_3531 {
  strings:
    $key_3531 = { 61 59 [2] 15 41 [2] 52 43 [2] 15 52 [2] 5b 5e [2] 57 54 [2] 40 5f [2] 5b 11 [2] 66 }

  condition:
    any of them
}