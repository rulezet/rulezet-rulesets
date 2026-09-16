rule TTP_XOR_MULT_DOSStub_bc6e {
  strings:
    $key_bc6e = { e8 06 [2] 9c 1e [2] db 1c [2] 9c 0d [2] d2 01 [2] de 0b [2] c9 00 [2] d2 4e [2] ef }

  condition:
    any of them
}