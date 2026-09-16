rule TTP_XOR_MULT_DOSStub_2d7c {
  strings:
    $key_2d7c = { 79 14 [2] 0d 0c [2] 4a 0e [2] 0d 1f [2] 43 13 [2] 4f 19 [2] 58 12 [2] 43 5c [2] 7e }

  condition:
    any of them
}