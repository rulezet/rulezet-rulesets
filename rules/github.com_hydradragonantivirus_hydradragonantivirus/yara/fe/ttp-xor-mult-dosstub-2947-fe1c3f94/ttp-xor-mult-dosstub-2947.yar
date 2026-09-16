rule TTP_XOR_MULT_DOSStub_2947 {
  strings:
    $key_2947 = { 7d 2f [2] 09 37 [2] 4e 35 [2] 09 24 [2] 47 28 [2] 4b 22 [2] 5c 29 [2] 47 67 [2] 7a }

  condition:
    any of them
}