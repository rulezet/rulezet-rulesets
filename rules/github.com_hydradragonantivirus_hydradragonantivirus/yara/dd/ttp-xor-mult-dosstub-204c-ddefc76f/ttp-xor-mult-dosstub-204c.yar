rule TTP_XOR_MULT_DOSStub_204c {
  strings:
    $key_204c = { 74 24 [2] 00 3c [2] 47 3e [2] 00 2f [2] 4e 23 [2] 42 29 [2] 55 22 [2] 4e 6c [2] 73 }

  condition:
    any of them
}