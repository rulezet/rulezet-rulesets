rule TTP_XOR_MULT_DOSStub_633d {
  strings:
    $key_633d = { 37 55 [2] 43 4d [2] 04 4f [2] 43 5e [2] 0d 52 [2] 01 58 [2] 16 53 [2] 0d 1d [2] 30 }

  condition:
    any of them
}