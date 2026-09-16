rule TTP_XOR_MULT_DOSStub_e947 {
  strings:
    $key_e947 = { bd 2f [2] c9 37 [2] 8e 35 [2] c9 24 [2] 87 28 [2] 8b 22 [2] 9c 29 [2] 87 67 [2] ba }

  condition:
    any of them
}