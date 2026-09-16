rule TTP_XOR_MULT_DOSStub_1bec {
  strings:
    $key_1bec = { 4f 84 [2] 3b 9c [2] 7c 9e [2] 3b 8f [2] 75 83 [2] 79 89 [2] 6e 82 [2] 75 cc [2] 48 }

  condition:
    any of them
}