rule TTP_XOR_MULT_DOSStub_646d {
  strings:
    $key_646d = { 30 05 [2] 44 1d [2] 03 1f [2] 44 0e [2] 0a 02 [2] 06 08 [2] 11 03 [2] 0a 4d [2] 37 }

  condition:
    any of them
}