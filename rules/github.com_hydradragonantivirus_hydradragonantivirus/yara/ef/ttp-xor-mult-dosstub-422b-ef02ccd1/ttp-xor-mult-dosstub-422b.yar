rule TTP_XOR_MULT_DOSStub_422b {
  strings:
    $key_422b = { 16 43 [2] 62 5b [2] 25 59 [2] 62 48 [2] 2c 44 [2] 20 4e [2] 37 45 [2] 2c 0b [2] 11 }

  condition:
    any of them
}