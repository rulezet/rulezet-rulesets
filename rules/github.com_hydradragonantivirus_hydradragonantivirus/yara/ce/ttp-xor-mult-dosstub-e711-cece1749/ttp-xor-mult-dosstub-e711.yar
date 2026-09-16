rule TTP_XOR_MULT_DOSStub_e711 {
  strings:
    $key_e711 = { b3 79 [2] c7 61 [2] 80 63 [2] c7 72 [2] 89 7e [2] 85 74 [2] 92 7f [2] 89 31 [2] b4 }

  condition:
    any of them
}