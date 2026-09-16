rule TTP_XOR_MULT_DOSStub_bc30 {
  strings:
    $key_bc30 = { e8 58 [2] 9c 40 [2] db 42 [2] 9c 53 [2] d2 5f [2] de 55 [2] c9 5e [2] d2 10 [2] ef }

  condition:
    any of them
}