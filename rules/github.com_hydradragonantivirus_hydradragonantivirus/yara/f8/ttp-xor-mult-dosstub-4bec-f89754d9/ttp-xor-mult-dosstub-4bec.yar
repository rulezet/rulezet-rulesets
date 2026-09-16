rule TTP_XOR_MULT_DOSStub_4bec {
  strings:
    $key_4bec = { 1f 84 [2] 6b 9c [2] 2c 9e [2] 6b 8f [2] 25 83 [2] 29 89 [2] 3e 82 [2] 25 cc [2] 18 }

  condition:
    any of them
}