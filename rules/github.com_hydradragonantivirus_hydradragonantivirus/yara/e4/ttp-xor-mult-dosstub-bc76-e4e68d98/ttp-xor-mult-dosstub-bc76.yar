rule TTP_XOR_MULT_DOSStub_bc76 {
  strings:
    $key_bc76 = { e8 1e [2] 9c 06 [2] db 04 [2] 9c 15 [2] d2 19 [2] de 13 [2] c9 18 [2] d2 56 [2] ef }

  condition:
    any of them
}