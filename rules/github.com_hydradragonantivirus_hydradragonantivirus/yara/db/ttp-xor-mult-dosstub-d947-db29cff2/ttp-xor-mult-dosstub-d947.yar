rule TTP_XOR_MULT_DOSStub_d947 {
  strings:
    $key_d947 = { 8d 2f [2] f9 37 [2] be 35 [2] f9 24 [2] b7 28 [2] bb 22 [2] ac 29 [2] b7 67 [2] 8a }

  condition:
    any of them
}