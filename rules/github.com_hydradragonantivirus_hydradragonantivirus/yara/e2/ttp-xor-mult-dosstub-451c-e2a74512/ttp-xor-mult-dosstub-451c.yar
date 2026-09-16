rule TTP_XOR_MULT_DOSStub_451c {
  strings:
    $key_451c = { 11 74 [2] 65 6c [2] 22 6e [2] 65 7f [2] 2b 73 [2] 27 79 [2] 30 72 [2] 2b 3c [2] 16 }

  condition:
    any of them
}