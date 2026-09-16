rule TTP_XOR_MULT_DOSStub_421b {
  strings:
    $key_421b = { 16 73 [2] 62 6b [2] 25 69 [2] 62 78 [2] 2c 74 [2] 20 7e [2] 37 75 [2] 2c 3b [2] 11 }

  condition:
    any of them
}