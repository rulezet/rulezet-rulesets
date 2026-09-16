rule TTP_XOR_MULT_DOSStub_1b1e {
  strings:
    $key_1b1e = { 4f 76 [2] 3b 6e [2] 7c 6c [2] 3b 7d [2] 75 71 [2] 79 7b [2] 6e 70 [2] 75 3e [2] 48 }

  condition:
    any of them
}