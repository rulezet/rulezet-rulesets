rule TTP_XOR_MULT_DOSStub_702b {
  strings:
    $key_702b = { 24 43 [2] 50 5b [2] 17 59 [2] 50 48 [2] 1e 44 [2] 12 4e [2] 05 45 [2] 1e 0b [2] 23 }

  condition:
    any of them
}