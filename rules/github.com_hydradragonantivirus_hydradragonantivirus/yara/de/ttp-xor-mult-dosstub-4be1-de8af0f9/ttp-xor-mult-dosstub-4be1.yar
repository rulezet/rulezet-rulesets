rule TTP_XOR_MULT_DOSStub_4be1 {
  strings:
    $key_4be1 = { 1f 89 [2] 6b 91 [2] 2c 93 [2] 6b 82 [2] 25 8e [2] 29 84 [2] 3e 8f [2] 25 c1 [2] 18 }

  condition:
    any of them
}