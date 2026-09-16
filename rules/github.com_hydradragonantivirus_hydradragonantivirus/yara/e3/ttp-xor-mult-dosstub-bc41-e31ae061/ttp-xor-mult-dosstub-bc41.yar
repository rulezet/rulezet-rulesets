rule TTP_XOR_MULT_DOSStub_bc41 {
  strings:
    $key_bc41 = { e8 29 [2] 9c 31 [2] db 33 [2] 9c 22 [2] d2 2e [2] de 24 [2] c9 2f [2] d2 61 [2] ef }

  condition:
    any of them
}