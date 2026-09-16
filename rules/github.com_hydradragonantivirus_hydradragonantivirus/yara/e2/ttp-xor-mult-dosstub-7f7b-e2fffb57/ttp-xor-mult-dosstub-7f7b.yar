rule TTP_XOR_MULT_DOSStub_7f7b {
  strings:
    $key_7f7b = { 2b 13 [2] 5f 0b [2] 18 09 [2] 5f 18 [2] 11 14 [2] 1d 1e [2] 0a 15 [2] 11 5b [2] 2c }

  condition:
    any of them
}