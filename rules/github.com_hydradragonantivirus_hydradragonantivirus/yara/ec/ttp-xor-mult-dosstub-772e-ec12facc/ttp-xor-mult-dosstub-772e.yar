rule TTP_XOR_MULT_DOSStub_772e {
  strings:
    $key_772e = { 23 46 [2] 57 5e [2] 10 5c [2] 57 4d [2] 19 41 [2] 15 4b [2] 02 40 [2] 19 0e [2] 24 }

  condition:
    any of them
}