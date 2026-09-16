rule TTP_XOR_MULT_DOSStub_7e40 {
  strings:
    $key_7e40 = { 2a 28 [2] 5e 30 [2] 19 32 [2] 5e 23 [2] 10 2f [2] 1c 25 [2] 0b 2e [2] 10 60 [2] 2d }

  condition:
    any of them
}