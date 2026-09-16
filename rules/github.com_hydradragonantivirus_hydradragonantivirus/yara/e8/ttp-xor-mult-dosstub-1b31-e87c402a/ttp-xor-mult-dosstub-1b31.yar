rule TTP_XOR_MULT_DOSStub_1b31 {
  strings:
    $key_1b31 = { 4f 59 [2] 3b 41 [2] 7c 43 [2] 3b 52 [2] 75 5e [2] 79 54 [2] 6e 5f [2] 75 11 [2] 48 }

  condition:
    any of them
}