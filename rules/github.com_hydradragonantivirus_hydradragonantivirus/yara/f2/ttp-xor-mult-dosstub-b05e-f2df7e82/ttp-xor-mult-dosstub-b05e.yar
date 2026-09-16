rule TTP_XOR_MULT_DOSStub_b05e {
  strings:
    $key_b05e = { e4 36 [2] 90 2e [2] d7 2c [2] 90 3d [2] de 31 [2] d2 3b [2] c5 30 [2] de 7e [2] e3 }

  condition:
    any of them
}