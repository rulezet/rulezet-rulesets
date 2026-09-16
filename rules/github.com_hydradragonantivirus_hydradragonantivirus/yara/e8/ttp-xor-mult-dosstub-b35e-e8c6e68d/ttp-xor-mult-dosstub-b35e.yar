rule TTP_XOR_MULT_DOSStub_b35e {
  strings:
    $key_b35e = { e7 36 [2] 93 2e [2] d4 2c [2] 93 3d [2] dd 31 [2] d1 3b [2] c6 30 [2] dd 7e [2] e0 }

  condition:
    any of them
}