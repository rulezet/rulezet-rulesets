rule TTP_XOR_MULT_DOSStub_5e4c {
  strings:
    $key_5e4c = { 0a 24 [2] 7e 3c [2] 39 3e [2] 7e 2f [2] 30 23 [2] 3c 29 [2] 2b 22 [2] 30 6c [2] 0d }

  condition:
    any of them
}