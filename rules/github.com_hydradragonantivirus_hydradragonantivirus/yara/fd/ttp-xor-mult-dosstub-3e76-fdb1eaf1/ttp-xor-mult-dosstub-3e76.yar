rule TTP_XOR_MULT_DOSStub_3e76 {
  strings:
    $key_3e76 = { 6a 1e [2] 1e 06 [2] 59 04 [2] 1e 15 [2] 50 19 [2] 5c 13 [2] 4b 18 [2] 50 56 [2] 6d }

  condition:
    any of them
}