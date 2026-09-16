rule TTP_XOR_MULT_DOSStub_0947 {
  strings:
    $key_0947 = { 5d 2f [2] 29 37 [2] 6e 35 [2] 29 24 [2] 67 28 [2] 6b 22 [2] 7c 29 [2] 67 67 [2] 5a }

  condition:
    any of them
}