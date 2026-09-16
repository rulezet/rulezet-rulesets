rule TTP_XOR_MULT_DOSStub_4d06 {
  strings:
    $key_4d06 = { 19 6e [2] 6d 76 [2] 2a 74 [2] 6d 65 [2] 23 69 [2] 2f 63 [2] 38 68 [2] 23 26 [2] 1e }

  condition:
    any of them
}