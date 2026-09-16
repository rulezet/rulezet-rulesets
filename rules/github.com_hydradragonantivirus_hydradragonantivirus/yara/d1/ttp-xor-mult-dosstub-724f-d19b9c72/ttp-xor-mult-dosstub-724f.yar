rule TTP_XOR_MULT_DOSStub_724f {
  strings:
    $key_724f = { 26 27 [2] 52 3f [2] 15 3d [2] 52 2c [2] 1c 20 [2] 10 2a [2] 07 21 [2] 1c 6f [2] 21 }

  condition:
    any of them
}