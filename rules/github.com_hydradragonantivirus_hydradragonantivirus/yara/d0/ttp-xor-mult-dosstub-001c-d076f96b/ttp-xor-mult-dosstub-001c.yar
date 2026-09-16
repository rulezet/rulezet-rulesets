rule TTP_XOR_MULT_DOSStub_001c {
  strings:
    $key_001c = { 54 74 [2] 20 6c [2] 67 6e [2] 20 7f [2] 6e 73 [2] 62 79 [2] 75 72 [2] 6e 3c [2] 53 }

  condition:
    any of them
}