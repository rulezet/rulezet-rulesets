rule TTP_XOR_MULT_DOSStub_5d1c {
  strings:
    $key_5d1c = { 09 74 [2] 7d 6c [2] 3a 6e [2] 7d 7f [2] 33 73 [2] 3f 79 [2] 28 72 [2] 33 3c [2] 0e }

  condition:
    any of them
}