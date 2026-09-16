rule TTP_XOR_MULT_DOSStub_7f2b {
  strings:
    $key_7f2b = { 2b 43 [2] 5f 5b [2] 18 59 [2] 5f 48 [2] 11 44 [2] 1d 4e [2] 0a 45 [2] 11 0b [2] 2c }

  condition:
    any of them
}