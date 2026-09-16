rule TTP_XOR_MULT_DOSStub_bc7b {
  strings:
    $key_bc7b = { e8 13 [2] 9c 0b [2] db 09 [2] 9c 18 [2] d2 14 [2] de 1e [2] c9 15 [2] d2 5b [2] ef }

  condition:
    any of them
}