rule TTP_XOR_MULT_DOSStub_bc37 {
  strings:
    $key_bc37 = { e8 5f [2] 9c 47 [2] db 45 [2] 9c 54 [2] d2 58 [2] de 52 [2] c9 59 [2] d2 17 [2] ef }

  condition:
    any of them
}