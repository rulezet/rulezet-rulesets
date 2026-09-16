rule TTP_XOR_MULT_DOSStub_7a5b {
  strings:
    $key_7a5b = { 2e 33 [2] 5a 2b [2] 1d 29 [2] 5a 38 [2] 14 34 [2] 18 3e [2] 0f 35 [2] 14 7b [2] 29 }

  condition:
    any of them
}