rule TTP_XOR_MULT_DOSStub_1e4c {
  strings:
    $key_1e4c = { 4a 24 [2] 3e 3c [2] 79 3e [2] 3e 2f [2] 70 23 [2] 7c 29 [2] 6b 22 [2] 70 6c [2] 4d }

  condition:
    any of them
}