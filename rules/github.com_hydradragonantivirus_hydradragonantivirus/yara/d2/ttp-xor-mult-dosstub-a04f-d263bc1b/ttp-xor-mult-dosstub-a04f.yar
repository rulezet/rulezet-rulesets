rule TTP_XOR_MULT_DOSStub_a04f {
  strings:
    $key_a04f = { f4 27 [2] 80 3f [2] c7 3d [2] 80 2c [2] ce 20 [2] c2 2a [2] d5 21 [2] ce 6f [2] f3 }

  condition:
    any of them
}