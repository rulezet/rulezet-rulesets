rule TTP_XOR_MULT_DOSStub_5d6e {
  strings:
    $key_5d6e = { 09 06 [2] 7d 1e [2] 3a 1c [2] 7d 0d [2] 33 01 [2] 3f 0b [2] 28 00 [2] 33 4e [2] 0e }

  condition:
    any of them
}