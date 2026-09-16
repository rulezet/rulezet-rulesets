rule TTP_XOR_MULT_DOSStub_427b {
  strings:
    $key_427b = { 16 13 [2] 62 0b [2] 25 09 [2] 62 18 [2] 2c 14 [2] 20 1e [2] 37 15 [2] 2c 5b [2] 11 }

  condition:
    any of them
}