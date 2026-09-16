rule TTP_XOR_MULT_DOSStub_2e36 {
  strings:
    $key_2e36 = { 7a 5e [2] 0e 46 [2] 49 44 [2] 0e 55 [2] 40 59 [2] 4c 53 [2] 5b 58 [2] 40 16 [2] 7d }

  condition:
    any of them
}