rule TTP_XOR_MULT_DOSStub_633c {
  strings:
    $key_633c = { 37 54 [2] 43 4c [2] 04 4e [2] 43 5f [2] 0d 53 [2] 01 59 [2] 16 52 [2] 0d 1c [2] 30 }

  condition:
    any of them
}