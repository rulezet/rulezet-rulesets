rule TTP_XOR_MULT_DOSStub_e05d {
  strings:
    $key_e05d = { b4 35 [2] c0 2d [2] 87 2f [2] c0 3e [2] 8e 32 [2] 82 38 [2] 95 33 [2] 8e 7d [2] b3 }

  condition:
    any of them
}