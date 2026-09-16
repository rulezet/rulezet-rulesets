rule TTP_XOR_MULT_DOSStub_0eec {
  strings:
    $key_0eec = { 5a 84 [2] 2e 9c [2] 69 9e [2] 2e 8f [2] 60 83 [2] 6c 89 [2] 7b 82 [2] 60 cc [2] 5d }

  condition:
    any of them
}