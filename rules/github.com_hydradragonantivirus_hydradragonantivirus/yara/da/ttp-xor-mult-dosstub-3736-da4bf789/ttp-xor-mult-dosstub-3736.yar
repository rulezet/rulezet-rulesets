rule TTP_XOR_MULT_DOSStub_3736 {
  strings:
    $key_3736 = { 63 5e [2] 17 46 [2] 50 44 [2] 17 55 [2] 59 59 [2] 55 53 [2] 42 58 [2] 59 16 [2] 64 }

  condition:
    any of them
}