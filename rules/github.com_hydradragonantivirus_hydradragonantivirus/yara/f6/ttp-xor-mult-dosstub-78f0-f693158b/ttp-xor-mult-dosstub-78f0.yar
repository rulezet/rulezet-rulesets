rule TTP_XOR_MULT_DOSStub_78f0 {
  strings:
    $key_78f0 = { 2c 98 [2] 58 80 [2] 1f 82 [2] 58 93 [2] 16 9f [2] 1a 95 [2] 0d 9e [2] 16 d0 [2] 2b }

  condition:
    any of them
}