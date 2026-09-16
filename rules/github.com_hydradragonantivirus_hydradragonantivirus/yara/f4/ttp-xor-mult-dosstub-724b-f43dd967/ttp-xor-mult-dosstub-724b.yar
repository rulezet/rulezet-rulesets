rule TTP_XOR_MULT_DOSStub_724b {
  strings:
    $key_724b = { 26 23 [2] 52 3b [2] 15 39 [2] 52 28 [2] 1c 24 [2] 10 2e [2] 07 25 [2] 1c 6b [2] 21 }

  condition:
    any of them
}