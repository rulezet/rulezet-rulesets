rule TTP_XOR_MULT_DOSStub_7aec {
  strings:
    $key_7aec = { 2e 84 [2] 5a 9c [2] 1d 9e [2] 5a 8f [2] 14 83 [2] 18 89 [2] 0f 82 [2] 14 cc [2] 29 }

  condition:
    any of them
}