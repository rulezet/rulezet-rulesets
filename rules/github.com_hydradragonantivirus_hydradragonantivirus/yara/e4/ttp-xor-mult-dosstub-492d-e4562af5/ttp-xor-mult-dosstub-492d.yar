rule TTP_XOR_MULT_DOSStub_492d {
  strings:
    $key_492d = { 1d 45 [2] 69 5d [2] 2e 5f [2] 69 4e [2] 27 42 [2] 2b 48 [2] 3c 43 [2] 27 0d [2] 1a }

  condition:
    any of them
}