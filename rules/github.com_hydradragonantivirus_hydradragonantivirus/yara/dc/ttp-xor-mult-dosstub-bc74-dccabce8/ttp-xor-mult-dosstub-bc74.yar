rule TTP_XOR_MULT_DOSStub_bc74 {
  strings:
    $key_bc74 = { e8 1c [2] 9c 04 [2] db 06 [2] 9c 17 [2] d2 1b [2] de 11 [2] c9 1a [2] d2 54 [2] ef }

  condition:
    any of them
}