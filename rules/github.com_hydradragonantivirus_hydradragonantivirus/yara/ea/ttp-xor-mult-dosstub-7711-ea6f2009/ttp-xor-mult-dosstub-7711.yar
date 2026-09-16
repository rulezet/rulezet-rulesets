rule TTP_XOR_MULT_DOSStub_7711 {
  strings:
    $key_7711 = { 23 79 [2] 57 61 [2] 10 63 [2] 57 72 [2] 19 7e [2] 15 74 [2] 02 7f [2] 19 31 [2] 24 }

  condition:
    any of them
}