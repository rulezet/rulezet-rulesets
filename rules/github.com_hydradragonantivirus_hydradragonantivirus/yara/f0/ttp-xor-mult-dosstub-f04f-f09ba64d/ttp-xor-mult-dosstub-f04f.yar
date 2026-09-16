rule TTP_XOR_MULT_DOSStub_f04f {
  strings:
    $key_f04f = { a4 27 [2] d0 3f [2] 97 3d [2] d0 2c [2] 9e 20 [2] 92 2a [2] 85 21 [2] 9e 6f [2] a3 }

  condition:
    any of them
}