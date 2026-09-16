rule TTP_XOR_MULT_DOSStub_c24f {
  strings:
    $key_c24f = { 96 27 [2] e2 3f [2] a5 3d [2] e2 2c [2] ac 20 [2] a0 2a [2] b7 21 [2] ac 6f [2] 91 }

  condition:
    any of them
}