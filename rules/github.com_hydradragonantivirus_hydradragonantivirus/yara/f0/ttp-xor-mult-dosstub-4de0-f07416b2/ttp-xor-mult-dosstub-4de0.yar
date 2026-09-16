rule TTP_XOR_MULT_DOSStub_4de0 {
  strings:
    $key_4de0 = { 19 88 [2] 6d 90 [2] 2a 92 [2] 6d 83 [2] 23 8f [2] 2f 85 [2] 38 8e [2] 23 c0 [2] 1e }

  condition:
    any of them
}