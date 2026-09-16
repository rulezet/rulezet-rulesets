rule TTP_XOR_MULT_DOSStub_0e4e {
  strings:
    $key_0e4e = { 5a 26 [2] 2e 3e [2] 69 3c [2] 2e 2d [2] 60 21 [2] 6c 2b [2] 7b 20 [2] 60 6e [2] 5d }

  condition:
    any of them
}