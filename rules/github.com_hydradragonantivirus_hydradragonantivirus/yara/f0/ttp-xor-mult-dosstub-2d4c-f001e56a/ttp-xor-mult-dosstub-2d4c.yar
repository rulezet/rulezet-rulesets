rule TTP_XOR_MULT_DOSStub_2d4c {
  strings:
    $key_2d4c = { 79 24 [2] 0d 3c [2] 4a 3e [2] 0d 2f [2] 43 23 [2] 4f 29 [2] 58 22 [2] 43 6c [2] 7e }

  condition:
    any of them
}