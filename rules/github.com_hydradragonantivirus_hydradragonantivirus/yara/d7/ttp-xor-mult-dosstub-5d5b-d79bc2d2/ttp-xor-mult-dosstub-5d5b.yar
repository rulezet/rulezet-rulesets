rule TTP_XOR_MULT_DOSStub_5d5b {
  strings:
    $key_5d5b = { 09 33 [2] 7d 2b [2] 3a 29 [2] 7d 38 [2] 33 34 [2] 3f 3e [2] 28 35 [2] 33 7b [2] 0e }

  condition:
    any of them
}