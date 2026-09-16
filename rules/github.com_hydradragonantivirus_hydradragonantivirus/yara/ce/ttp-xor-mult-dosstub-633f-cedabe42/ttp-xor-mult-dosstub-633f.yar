rule TTP_XOR_MULT_DOSStub_633f {
  strings:
    $key_633f = { 37 57 [2] 43 4f [2] 04 4d [2] 43 5c [2] 0d 50 [2] 01 5a [2] 16 51 [2] 0d 1f [2] 30 }

  condition:
    any of them
}