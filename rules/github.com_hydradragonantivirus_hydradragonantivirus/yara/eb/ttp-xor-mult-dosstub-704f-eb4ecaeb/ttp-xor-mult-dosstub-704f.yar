rule TTP_XOR_MULT_DOSStub_704f {
  strings:
    $key_704f = { 24 27 [2] 50 3f [2] 17 3d [2] 50 2c [2] 1e 20 [2] 12 2a [2] 05 21 [2] 1e 6f [2] 23 }

  condition:
    any of them
}