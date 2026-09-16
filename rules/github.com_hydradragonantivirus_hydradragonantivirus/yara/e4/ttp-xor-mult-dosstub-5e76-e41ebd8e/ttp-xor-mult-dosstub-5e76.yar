rule TTP_XOR_MULT_DOSStub_5e76 {
  strings:
    $key_5e76 = { 0a 1e [2] 7e 06 [2] 39 04 [2] 7e 15 [2] 30 19 [2] 3c 13 [2] 2b 18 [2] 30 56 [2] 0d }

  condition:
    any of them
}