rule TTP_XOR_MULT_DOSStub_7f4c {
  strings:
    $key_7f4c = { 2b 24 [2] 5f 3c [2] 18 3e [2] 5f 2f [2] 11 23 [2] 1d 29 [2] 0a 22 [2] 11 6c [2] 2c }

  condition:
    any of them
}