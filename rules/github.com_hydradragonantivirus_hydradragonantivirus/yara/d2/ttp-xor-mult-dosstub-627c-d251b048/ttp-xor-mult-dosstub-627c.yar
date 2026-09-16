rule TTP_XOR_MULT_DOSStub_627c {
  strings:
    $key_627c = { 36 14 [2] 42 0c [2] 05 0e [2] 42 1f [2] 0c 13 [2] 00 19 [2] 17 12 [2] 0c 5c [2] 31 }

  condition:
    any of them
}