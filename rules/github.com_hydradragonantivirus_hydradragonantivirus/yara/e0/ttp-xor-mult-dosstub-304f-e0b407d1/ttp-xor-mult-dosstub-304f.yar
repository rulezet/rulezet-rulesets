rule TTP_XOR_MULT_DOSStub_304f {
  strings:
    $key_304f = { 64 27 [2] 10 3f [2] 57 3d [2] 10 2c [2] 5e 20 [2] 52 2a [2] 45 21 [2] 5e 6f [2] 63 }

  condition:
    any of them
}