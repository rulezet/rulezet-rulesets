rule TTP_XOR_MULT_DOSStub_263d {
  strings:
    $key_263d = { 72 55 [2] 06 4d [2] 41 4f [2] 06 5e [2] 48 52 [2] 44 58 [2] 53 53 [2] 48 1d [2] 75 }

  condition:
    any of them
}