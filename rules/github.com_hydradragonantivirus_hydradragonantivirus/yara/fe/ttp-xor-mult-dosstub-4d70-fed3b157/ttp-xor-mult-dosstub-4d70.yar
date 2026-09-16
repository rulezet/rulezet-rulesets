rule TTP_XOR_MULT_DOSStub_4d70 {
  strings:
    $key_4d70 = { 19 18 [2] 6d 00 [2] 2a 02 [2] 6d 13 [2] 23 1f [2] 2f 15 [2] 38 1e [2] 23 50 [2] 1e }

  condition:
    any of them
}