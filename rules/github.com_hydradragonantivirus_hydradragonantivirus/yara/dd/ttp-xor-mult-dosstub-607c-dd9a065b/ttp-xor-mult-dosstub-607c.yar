rule TTP_XOR_MULT_DOSStub_607c {
  strings:
    $key_607c = { 34 14 [2] 40 0c [2] 07 0e [2] 40 1f [2] 0e 13 [2] 02 19 [2] 15 12 [2] 0e 5c [2] 33 }

  condition:
    any of them
}