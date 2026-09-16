rule TTP_XOR_MULT_DOSStub_674c {
  strings:
    $key_674c = { 33 24 [2] 47 3c [2] 00 3e [2] 47 2f [2] 09 23 [2] 05 29 [2] 12 22 [2] 09 6c [2] 34 }

  condition:
    any of them
}