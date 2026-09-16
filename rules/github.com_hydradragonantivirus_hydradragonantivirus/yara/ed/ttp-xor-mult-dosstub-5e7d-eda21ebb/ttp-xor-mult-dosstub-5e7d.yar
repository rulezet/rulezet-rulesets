rule TTP_XOR_MULT_DOSStub_5e7d {
  strings:
    $key_5e7d = { 0a 15 [2] 7e 0d [2] 39 0f [2] 7e 1e [2] 30 12 [2] 3c 18 [2] 2b 13 [2] 30 5d [2] 0d }

  condition:
    any of them
}