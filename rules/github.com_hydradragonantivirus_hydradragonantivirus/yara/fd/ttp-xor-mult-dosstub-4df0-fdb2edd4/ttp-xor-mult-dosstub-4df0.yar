rule TTP_XOR_MULT_DOSStub_4df0 {
  strings:
    $key_4df0 = { 19 98 [2] 6d 80 [2] 2a 82 [2] 6d 93 [2] 23 9f [2] 2f 95 [2] 38 9e [2] 23 d0 [2] 1e }

  condition:
    any of them
}