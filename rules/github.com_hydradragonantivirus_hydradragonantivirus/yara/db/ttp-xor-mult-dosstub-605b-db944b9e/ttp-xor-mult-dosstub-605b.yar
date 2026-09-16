rule TTP_XOR_MULT_DOSStub_605b {
  strings:
    $key_605b = { 34 33 [2] 40 2b [2] 07 29 [2] 40 38 [2] 0e 34 [2] 02 3e [2] 15 35 [2] 0e 7b [2] 33 }

  condition:
    any of them
}