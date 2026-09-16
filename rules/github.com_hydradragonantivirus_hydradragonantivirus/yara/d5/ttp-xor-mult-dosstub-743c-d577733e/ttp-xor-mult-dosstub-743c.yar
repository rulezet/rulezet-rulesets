rule TTP_XOR_MULT_DOSStub_743c {
  strings:
    $key_743c = { 20 54 [2] 54 4c [2] 13 4e [2] 54 5f [2] 1a 53 [2] 16 59 [2] 01 52 [2] 1a 1c [2] 27 }

  condition:
    any of them
}