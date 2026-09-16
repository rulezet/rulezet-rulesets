rule TTP_XOR_MULT_DOSStub_bc04 {
  strings:
    $key_bc04 = { e8 6c [2] 9c 74 [2] db 76 [2] 9c 67 [2] d2 6b [2] de 61 [2] c9 6a [2] d2 24 [2] ef }

  condition:
    any of them
}