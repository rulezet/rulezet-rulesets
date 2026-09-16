rule TTP_XOR_MULT_DOSStub_bc7e {
  strings:
    $key_bc7e = { e8 16 [2] 9c 0e [2] db 0c [2] 9c 1d [2] d2 11 [2] de 1b [2] c9 10 [2] d2 5e [2] ef }

  condition:
    any of them
}