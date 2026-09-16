rule TTP_XOR_MULT_DOSStub_3b20 {
  strings:
    $key_3b20 = { 6f 48 [2] 1b 50 [2] 5c 52 [2] 1b 43 [2] 55 4f [2] 59 45 [2] 4e 4e [2] 55 00 [2] 68 }

  condition:
    any of them
}