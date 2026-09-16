rule TTP_XOR_MULT_DOSStub_4b50 {
  strings:
    $key_4b50 = { 1f 38 [2] 6b 20 [2] 2c 22 [2] 6b 33 [2] 25 3f [2] 29 35 [2] 3e 3e [2] 25 70 [2] 18 }

  condition:
    any of them
}