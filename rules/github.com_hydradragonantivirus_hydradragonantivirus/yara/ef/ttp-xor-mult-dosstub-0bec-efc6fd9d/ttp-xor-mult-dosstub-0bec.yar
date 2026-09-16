rule TTP_XOR_MULT_DOSStub_0bec {
  strings:
    $key_0bec = { 5f 84 [2] 2b 9c [2] 6c 9e [2] 2b 8f [2] 65 83 [2] 69 89 [2] 7e 82 [2] 65 cc [2] 58 }

  condition:
    any of them
}