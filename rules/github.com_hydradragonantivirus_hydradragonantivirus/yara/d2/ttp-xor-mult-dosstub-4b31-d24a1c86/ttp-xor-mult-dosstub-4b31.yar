rule TTP_XOR_MULT_DOSStub_4b31 {
  strings:
    $key_4b31 = { 1f 59 [2] 6b 41 [2] 2c 43 [2] 6b 52 [2] 25 5e [2] 29 54 [2] 3e 5f [2] 25 11 [2] 18 }

  condition:
    any of them
}