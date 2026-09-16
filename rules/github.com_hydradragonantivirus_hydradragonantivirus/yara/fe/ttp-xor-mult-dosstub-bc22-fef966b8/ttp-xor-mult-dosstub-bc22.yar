rule TTP_XOR_MULT_DOSStub_bc22 {
  strings:
    $key_bc22 = { e8 4a [2] 9c 52 [2] db 50 [2] 9c 41 [2] d2 4d [2] de 47 [2] c9 4c [2] d2 02 [2] ef }

  condition:
    any of them
}