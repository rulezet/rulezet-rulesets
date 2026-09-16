rule TTP_XOR_MULT_DOSStub_775b {
  strings:
    $key_775b = { 23 33 [2] 57 2b [2] 10 29 [2] 57 38 [2] 19 34 [2] 15 3e [2] 02 35 [2] 19 7b [2] 24 }

  condition:
    any of them
}