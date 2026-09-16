rule TTP_XOR_MULT_DOSStub_f44f {
  strings:
    $key_f44f = { a0 27 [2] d4 3f [2] 93 3d [2] d4 2c [2] 9a 20 [2] 96 2a [2] 81 21 [2] 9a 6f [2] a7 }

  condition:
    any of them
}