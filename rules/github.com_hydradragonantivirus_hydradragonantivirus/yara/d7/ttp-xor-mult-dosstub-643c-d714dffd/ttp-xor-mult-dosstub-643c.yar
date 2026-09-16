rule TTP_XOR_MULT_DOSStub_643c {
  strings:
    $key_643c = { 30 54 [2] 44 4c [2] 03 4e [2] 44 5f [2] 0a 53 [2] 06 59 [2] 11 52 [2] 0a 1c [2] 37 }

  condition:
    any of them
}