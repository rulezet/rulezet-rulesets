rule TTP_XOR_MULT_DOSStub_3231 {
  strings:
    $key_3231 = { 66 59 [2] 12 41 [2] 55 43 [2] 12 52 [2] 5c 5e [2] 50 54 [2] 47 5f [2] 5c 11 [2] 61 }

  condition:
    any of them
}