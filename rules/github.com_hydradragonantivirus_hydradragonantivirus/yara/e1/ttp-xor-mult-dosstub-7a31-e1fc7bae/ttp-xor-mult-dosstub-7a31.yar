rule TTP_XOR_MULT_DOSStub_7a31 {
  strings:
    $key_7a31 = { 2e 59 [2] 5a 41 [2] 1d 43 [2] 5a 52 [2] 14 5e [2] 18 54 [2] 0f 5f [2] 14 11 [2] 29 }

  condition:
    any of them
}