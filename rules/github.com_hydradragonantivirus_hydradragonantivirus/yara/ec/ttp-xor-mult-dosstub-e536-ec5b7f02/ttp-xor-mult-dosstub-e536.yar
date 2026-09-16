rule TTP_XOR_MULT_DOSStub_e536 {
  strings:
    $key_e536 = { b1 5e [2] c5 46 [2] 82 44 [2] c5 55 [2] 8b 59 [2] 87 53 [2] 90 58 [2] 8b 16 [2] b6 }

  condition:
    any of them
}