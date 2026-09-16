rule TTP_XOR_MULT_DOSStub_b54d {
  strings:
    $key_b54d = { e1 25 [2] 95 3d [2] d2 3f [2] 95 2e [2] db 22 [2] d7 28 [2] c0 23 [2] db 6d [2] e6 }

  condition:
    any of them
}