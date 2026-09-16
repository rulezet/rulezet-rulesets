rule TTP_XOR_MULT_DOSStub_bc2e {
  strings:
    $key_bc2e = { e8 46 [2] 9c 5e [2] db 5c [2] 9c 4d [2] d2 41 [2] de 4b [2] c9 40 [2] d2 0e [2] ef }

  condition:
    any of them
}