rule TTP_XOR_MULT_DOSStub_125b {
  strings:
    $key_125b = { 46 33 [2] 32 2b [2] 75 29 [2] 32 38 [2] 7c 34 [2] 70 3e [2] 67 35 [2] 7c 7b [2] 41 }

  condition:
    any of them
}