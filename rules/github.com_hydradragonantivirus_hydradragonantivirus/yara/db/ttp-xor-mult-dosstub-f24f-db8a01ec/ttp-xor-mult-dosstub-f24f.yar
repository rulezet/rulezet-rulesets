rule TTP_XOR_MULT_DOSStub_f24f {
  strings:
    $key_f24f = { a6 27 [2] d2 3f [2] 95 3d [2] d2 2c [2] 9c 20 [2] 90 2a [2] 87 21 [2] 9c 6f [2] a1 }

  condition:
    any of them
}