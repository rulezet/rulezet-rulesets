rule TTP_XOR_MULT_DOSStub_2eec {
  strings:
    $key_2eec = { 7a 84 [2] 0e 9c [2] 49 9e [2] 0e 8f [2] 40 83 [2] 4c 89 [2] 5b 82 [2] 40 cc [2] 7d }

  condition:
    any of them
}