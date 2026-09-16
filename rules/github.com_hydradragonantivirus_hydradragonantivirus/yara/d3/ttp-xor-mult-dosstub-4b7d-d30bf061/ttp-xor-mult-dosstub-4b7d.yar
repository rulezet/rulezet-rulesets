rule TTP_XOR_MULT_DOSStub_4b7d {
  strings:
    $key_4b7d = { 1f 15 [2] 6b 0d [2] 2c 0f [2] 6b 1e [2] 25 12 [2] 29 18 [2] 3e 13 [2] 25 5d [2] 18 }

  condition:
    any of them
}