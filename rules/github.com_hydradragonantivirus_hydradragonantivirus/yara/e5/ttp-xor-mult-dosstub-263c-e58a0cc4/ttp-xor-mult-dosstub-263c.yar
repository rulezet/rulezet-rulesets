rule TTP_XOR_MULT_DOSStub_263c {
  strings:
    $key_263c = { 72 54 [2] 06 4c [2] 41 4e [2] 06 5f [2] 48 53 [2] 44 59 [2] 53 52 [2] 48 1c [2] 75 }

  condition:
    any of them
}