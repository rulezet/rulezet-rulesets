rule TTP_XOR_MULT_DOSStub_5d6d {
  strings:
    $key_5d6d = { 09 05 [2] 7d 1d [2] 3a 1f [2] 7d 0e [2] 33 02 [2] 3f 08 [2] 28 03 [2] 33 4d [2] 0e }

  condition:
    any of them
}