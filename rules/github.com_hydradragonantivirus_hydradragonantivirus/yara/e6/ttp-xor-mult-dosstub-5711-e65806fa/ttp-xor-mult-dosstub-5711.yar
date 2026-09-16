rule TTP_XOR_MULT_DOSStub_5711 {
  strings:
    $key_5711 = { 03 79 [2] 77 61 [2] 30 63 [2] 77 72 [2] 39 7e [2] 35 74 [2] 22 7f [2] 39 31 [2] 04 }

  condition:
    any of them
}