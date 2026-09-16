rule TTP_XOR_MULT_DOSStub_5d4c {
  strings:
    $key_5d4c = { 09 24 [2] 7d 3c [2] 3a 3e [2] 7d 2f [2] 33 23 [2] 3f 29 [2] 28 22 [2] 33 6c [2] 0e }

  condition:
    any of them
}