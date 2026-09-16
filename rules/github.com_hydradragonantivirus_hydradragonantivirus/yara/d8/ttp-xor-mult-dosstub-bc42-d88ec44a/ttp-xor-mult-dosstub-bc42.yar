rule TTP_XOR_MULT_DOSStub_bc42 {
  strings:
    $key_bc42 = { e8 2a [2] 9c 32 [2] db 30 [2] 9c 21 [2] d2 2d [2] de 27 [2] c9 2c [2] d2 62 [2] ef }

  condition:
    any of them
}