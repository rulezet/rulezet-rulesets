rule TTP_XOR_MULT_DOSStub_7b31 {
  strings:
    $key_7b31 = { 2f 59 [2] 5b 41 [2] 1c 43 [2] 5b 52 [2] 15 5e [2] 19 54 [2] 0e 5f [2] 15 11 [2] 28 }

  condition:
    any of them
}