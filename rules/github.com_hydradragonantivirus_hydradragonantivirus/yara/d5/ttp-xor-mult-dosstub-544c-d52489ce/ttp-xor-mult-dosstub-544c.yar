rule TTP_XOR_MULT_DOSStub_544c {
  strings:
    $key_544c = { 00 24 [2] 74 3c [2] 33 3e [2] 74 2f [2] 3a 23 [2] 36 29 [2] 21 22 [2] 3a 6c [2] 07 }

  condition:
    any of them
}