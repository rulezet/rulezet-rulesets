rule TTP_XOR_MULT_DOSStub_2920 {
  strings:
    $key_2920 = { 7d 48 [2] 09 50 [2] 4e 52 [2] 09 43 [2] 47 4f [2] 4b 45 [2] 5c 4e [2] 47 00 [2] 7a }

  condition:
    any of them
}