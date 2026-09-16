rule TTP_XOR_MULT_DOSStub_bc13 {
  strings:
    $key_bc13 = { e8 7b [2] 9c 63 [2] db 61 [2] 9c 70 [2] d2 7c [2] de 76 [2] c9 7d [2] d2 33 [2] ef }

  condition:
    any of them
}