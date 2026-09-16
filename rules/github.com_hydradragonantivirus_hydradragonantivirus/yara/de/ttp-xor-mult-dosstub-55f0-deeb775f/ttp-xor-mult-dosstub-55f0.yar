rule TTP_XOR_MULT_DOSStub_55f0 {
  strings:
    $key_55f0 = { 01 98 [2] 75 80 [2] 32 82 [2] 75 93 [2] 3b 9f [2] 37 95 [2] 20 9e [2] 3b d0 [2] 06 }

  condition:
    any of them
}