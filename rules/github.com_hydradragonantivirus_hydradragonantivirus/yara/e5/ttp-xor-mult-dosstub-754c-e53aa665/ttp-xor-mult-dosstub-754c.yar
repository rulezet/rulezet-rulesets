rule TTP_XOR_MULT_DOSStub_754c {
  strings:
    $key_754c = { 21 24 [2] 55 3c [2] 12 3e [2] 55 2f [2] 1b 23 [2] 17 29 [2] 00 22 [2] 1b 6c [2] 26 }

  condition:
    any of them
}