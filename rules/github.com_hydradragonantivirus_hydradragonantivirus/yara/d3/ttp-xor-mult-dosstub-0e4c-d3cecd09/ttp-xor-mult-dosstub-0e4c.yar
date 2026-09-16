rule TTP_XOR_MULT_DOSStub_0e4c {
  strings:
    $key_0e4c = { 5a 24 [2] 2e 3c [2] 69 3e [2] 2e 2f [2] 60 23 [2] 6c 29 [2] 7b 22 [2] 60 6c [2] 5d }

  condition:
    any of them
}