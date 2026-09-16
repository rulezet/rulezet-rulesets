rule TTP_XOR_MULT_DOSStub_415b {
  strings:
    $key_415b = { 15 33 [2] 61 2b [2] 26 29 [2] 61 38 [2] 2f 34 [2] 23 3e [2] 34 35 [2] 2f 7b [2] 12 }

  condition:
    any of them
}