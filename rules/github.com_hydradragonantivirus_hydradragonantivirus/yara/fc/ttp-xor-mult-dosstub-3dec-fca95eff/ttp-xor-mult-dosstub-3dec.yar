rule TTP_XOR_MULT_DOSStub_3dec {
  strings:
    $key_3dec = { 69 84 [2] 1d 9c [2] 5a 9e [2] 1d 8f [2] 53 83 [2] 5f 89 [2] 48 82 [2] 53 cc [2] 6e }

  condition:
    any of them
}