rule TTP_XOR_MULT_DOSStub_372b {
  strings:
    $key_372b = { 63 43 [2] 17 5b [2] 50 59 [2] 17 48 [2] 59 44 [2] 55 4e [2] 42 45 [2] 59 0b [2] 64 }

  condition:
    any of them
}