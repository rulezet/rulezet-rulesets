rule TTP_XOR_MULT_DOSStub_b75e {
  strings:
    $key_b75e = { e3 36 [2] 97 2e [2] d0 2c [2] 97 3d [2] d9 31 [2] d5 3b [2] c2 30 [2] d9 7e [2] e4 }

  condition:
    any of them
}