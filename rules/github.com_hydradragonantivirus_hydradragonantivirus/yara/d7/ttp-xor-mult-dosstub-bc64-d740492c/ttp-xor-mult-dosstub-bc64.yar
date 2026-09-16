rule TTP_XOR_MULT_DOSStub_bc64 {
  strings:
    $key_bc64 = { e8 0c [2] 9c 14 [2] db 16 [2] 9c 07 [2] d2 0b [2] de 01 [2] c9 0a [2] d2 44 [2] ef }

  condition:
    any of them
}