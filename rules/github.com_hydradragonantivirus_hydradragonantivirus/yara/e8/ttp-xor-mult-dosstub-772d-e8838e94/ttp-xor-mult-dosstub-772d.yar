rule TTP_XOR_MULT_DOSStub_772d {
  strings:
    $key_772d = { 23 45 [2] 57 5d [2] 10 5f [2] 57 4e [2] 19 42 [2] 15 48 [2] 02 43 [2] 19 0d [2] 24 }

  condition:
    any of them
}