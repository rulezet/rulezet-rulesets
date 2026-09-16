rule TTP_XOR_MULT_DOSStub_7e76 {
  strings:
    $key_7e76 = { 2a 1e [2] 5e 06 [2] 19 04 [2] 5e 15 [2] 10 19 [2] 1c 13 [2] 0b 18 [2] 10 56 [2] 2d }

  condition:
    any of them
}