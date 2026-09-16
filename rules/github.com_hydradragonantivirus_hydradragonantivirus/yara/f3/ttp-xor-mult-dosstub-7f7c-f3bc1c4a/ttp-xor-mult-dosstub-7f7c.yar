rule TTP_XOR_MULT_DOSStub_7f7c {
  strings:
    $key_7f7c = { 2b 14 [2] 5f 0c [2] 18 0e [2] 5f 1f [2] 11 13 [2] 1d 19 [2] 0a 12 [2] 11 5c [2] 2c }

  condition:
    any of them
}