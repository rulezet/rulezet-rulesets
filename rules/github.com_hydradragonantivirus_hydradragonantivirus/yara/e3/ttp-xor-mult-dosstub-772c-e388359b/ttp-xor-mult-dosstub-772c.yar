rule TTP_XOR_MULT_DOSStub_772c {
  strings:
    $key_772c = { 23 44 [2] 57 5c [2] 10 5e [2] 57 4f [2] 19 43 [2] 15 49 [2] 02 42 [2] 19 0c [2] 24 }

  condition:
    any of them
}