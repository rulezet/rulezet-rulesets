rule TTP_XOR_MULT_DOSStub_4e3e {
  strings:
    $key_4e3e = { 1a 56 [2] 6e 4e [2] 29 4c [2] 6e 5d [2] 20 51 [2] 2c 5b [2] 3b 50 [2] 20 1e [2] 1d }

  condition:
    any of them
}