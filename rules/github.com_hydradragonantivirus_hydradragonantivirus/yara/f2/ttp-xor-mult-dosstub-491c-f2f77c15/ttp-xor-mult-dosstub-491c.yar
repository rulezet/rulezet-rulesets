rule TTP_XOR_MULT_DOSStub_491c {
  strings:
    $key_491c = { 1d 74 [2] 69 6c [2] 2e 6e [2] 69 7f [2] 27 73 [2] 2b 79 [2] 3c 72 [2] 27 3c [2] 1a }

  condition:
    any of them
}