rule TTP_XOR_MULT_DOSStub_b04d {
  strings:
    $key_b04d = { e4 25 [2] 90 3d [2] d7 3f [2] 90 2e [2] de 22 [2] d2 28 [2] c5 23 [2] de 6d [2] e3 }

  condition:
    any of them
}