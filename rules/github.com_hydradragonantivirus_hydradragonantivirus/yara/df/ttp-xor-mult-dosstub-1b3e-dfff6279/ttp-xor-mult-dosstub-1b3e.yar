rule TTP_XOR_MULT_DOSStub_1b3e {
  strings:
    $key_1b3e = { 4f 56 [2] 3b 4e [2] 7c 4c [2] 3b 5d [2] 75 51 [2] 79 5b [2] 6e 50 [2] 75 1e [2] 48 }

  condition:
    any of them
}