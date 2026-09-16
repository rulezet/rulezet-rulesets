rule TTP_XOR_MULT_DOSStub_e840 {
  strings:
    $key_e840 = { bc 28 [2] c8 30 [2] 8f 32 [2] c8 23 [2] 86 2f [2] 8a 25 [2] 9d 2e [2] 86 60 [2] bb }

  condition:
    any of them
}