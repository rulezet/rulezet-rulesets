rule TTP_XOR_MULT_DOSStub_4e7c {
  strings:
    $key_4e7c = { 1a 14 [2] 6e 0c [2] 29 0e [2] 6e 1f [2] 20 13 [2] 2c 19 [2] 3b 12 [2] 20 5c [2] 1d }

  condition:
    any of them
}