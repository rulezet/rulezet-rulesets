rule TTP_XOR_MULT_DOSStub_671c {
  strings:
    $key_671c = { 33 74 [2] 47 6c [2] 00 6e [2] 47 7f [2] 09 73 [2] 05 79 [2] 12 72 [2] 09 3c [2] 34 }

  condition:
    any of them
}