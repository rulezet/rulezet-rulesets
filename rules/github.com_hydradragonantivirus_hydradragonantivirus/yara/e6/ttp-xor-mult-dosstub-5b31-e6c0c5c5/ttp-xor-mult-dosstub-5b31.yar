rule TTP_XOR_MULT_DOSStub_5b31 {
  strings:
    $key_5b31 = { 0f 59 [2] 7b 41 [2] 3c 43 [2] 7b 52 [2] 35 5e [2] 39 54 [2] 2e 5f [2] 35 11 [2] 08 }

  condition:
    any of them
}