rule TTP_XOR_MULT_DOSStub_261c {
  strings:
    $key_261c = { 72 74 [2] 06 6c [2] 41 6e [2] 06 7f [2] 48 73 [2] 44 79 [2] 53 72 [2] 48 3c [2] 75 }

  condition:
    any of them
}