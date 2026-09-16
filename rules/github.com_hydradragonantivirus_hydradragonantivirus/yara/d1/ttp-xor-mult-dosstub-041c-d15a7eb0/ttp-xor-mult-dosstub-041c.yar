rule TTP_XOR_MULT_DOSStub_041c {
  strings:
    $key_041c = { 50 74 [2] 24 6c [2] 63 6e [2] 24 7f [2] 6a 73 [2] 66 79 [2] 71 72 [2] 6a 3c [2] 57 }

  condition:
    any of them
}