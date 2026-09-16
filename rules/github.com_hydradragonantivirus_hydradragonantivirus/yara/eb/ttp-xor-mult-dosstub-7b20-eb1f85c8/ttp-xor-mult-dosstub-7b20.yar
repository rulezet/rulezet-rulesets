rule TTP_XOR_MULT_DOSStub_7b20 {
  strings:
    $key_7b20 = { 2f 48 [2] 5b 50 [2] 1c 52 [2] 5b 43 [2] 15 4f [2] 19 45 [2] 0e 4e [2] 15 00 [2] 28 }

  condition:
    any of them
}