rule TTP_XOR_MULT_DOSStub_005b {
  strings:
    $key_005b = { 54 33 [2] 20 2b [2] 67 29 [2] 20 38 [2] 6e 34 [2] 62 3e [2] 75 35 [2] 6e 7b [2] 53 }

  condition:
    any of them
}