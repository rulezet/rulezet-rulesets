rule TTP_XOR_MULT_DOSStub_744c {
  strings:
    $key_744c = { 20 24 [2] 54 3c [2] 13 3e [2] 54 2f [2] 1a 23 [2] 16 29 [2] 01 22 [2] 1a 6c [2] 27 }

  condition:
    any of them
}