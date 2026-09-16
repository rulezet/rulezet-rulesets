rule TTP_XOR_MULT_DOSStub_4b7b {
  strings:
    $key_4b7b = { 1f 13 [2] 6b 0b [2] 2c 09 [2] 6b 18 [2] 25 14 [2] 29 1e [2] 3e 15 [2] 25 5b [2] 18 }

  condition:
    any of them
}