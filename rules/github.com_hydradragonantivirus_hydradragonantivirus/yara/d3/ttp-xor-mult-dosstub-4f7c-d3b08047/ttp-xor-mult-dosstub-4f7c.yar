rule TTP_XOR_MULT_DOSStub_4f7c {
  strings:
    $key_4f7c = { 1b 14 [2] 6f 0c [2] 28 0e [2] 6f 1f [2] 21 13 [2] 2d 19 [2] 3a 12 [2] 21 5c [2] 1c }

  condition:
    any of them
}