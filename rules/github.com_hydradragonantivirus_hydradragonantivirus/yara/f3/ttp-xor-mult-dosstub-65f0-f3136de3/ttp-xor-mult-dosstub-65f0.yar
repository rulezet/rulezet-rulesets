rule TTP_XOR_MULT_DOSStub_65f0 {
  strings:
    $key_65f0 = { 31 98 [2] 45 80 [2] 02 82 [2] 45 93 [2] 0b 9f [2] 07 95 [2] 10 9e [2] 0b d0 [2] 36 }

  condition:
    any of them
}