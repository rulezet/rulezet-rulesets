rule TTP_XOR_MULT_DOSStub_355b {
  strings:
    $key_355b = { 61 33 [2] 15 2b [2] 52 29 [2] 15 38 [2] 5b 34 [2] 57 3e [2] 40 35 [2] 5b 7b [2] 66 }

  condition:
    any of them
}