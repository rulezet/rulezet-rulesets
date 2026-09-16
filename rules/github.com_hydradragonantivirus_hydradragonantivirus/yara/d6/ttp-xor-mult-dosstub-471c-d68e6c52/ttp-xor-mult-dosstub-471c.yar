rule TTP_XOR_MULT_DOSStub_471c {
  strings:
    $key_471c = { 13 74 [2] 67 6c [2] 20 6e [2] 67 7f [2] 29 73 [2] 25 79 [2] 32 72 [2] 29 3c [2] 14 }

  condition:
    any of them
}