rule TTP_XOR_MULT_DOSStub_7b76 {
  strings:
    $key_7b76 = { 2f 1e [2] 5b 06 [2] 1c 04 [2] 5b 15 [2] 15 19 [2] 19 13 [2] 0e 18 [2] 15 56 [2] 28 }

  condition:
    any of them
}