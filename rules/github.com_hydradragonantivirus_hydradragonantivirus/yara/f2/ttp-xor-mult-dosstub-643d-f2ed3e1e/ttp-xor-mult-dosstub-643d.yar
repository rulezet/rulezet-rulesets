rule TTP_XOR_MULT_DOSStub_643d {
  strings:
    $key_643d = { 30 55 [2] 44 4d [2] 03 4f [2] 44 5e [2] 0a 52 [2] 06 58 [2] 11 53 [2] 0a 1d [2] 37 }

  condition:
    any of them
}