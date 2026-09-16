rule TTP_XOR_MULT_DOSStub_bc7d {
  strings:
    $key_bc7d = { e8 15 [2] 9c 0d [2] db 0f [2] 9c 1e [2] d2 12 [2] de 18 [2] c9 13 [2] d2 5d [2] ef }

  condition:
    any of them
}