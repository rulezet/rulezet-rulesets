rule TTP_XOR_MULT_DOSStub_044d {
  strings:
    $key_044d = { 50 25 [2] 24 3d [2] 63 3f [2] 24 2e [2] 6a 22 [2] 66 28 [2] 71 23 [2] 6a 6d [2] 57 }

  condition:
    any of them
}