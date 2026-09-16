rule TTP_XOR_MULT_DOSStub_bc00 {
  strings:
    $key_bc00 = { e8 68 [2] 9c 70 [2] db 72 [2] 9c 63 [2] d2 6f [2] de 65 [2] c9 6e [2] d2 20 [2] ef }

  condition:
    any of them
}