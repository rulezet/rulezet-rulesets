rule TTP_XOR_MULT_DOSStub_e65d {
  strings:
    $key_e65d = { b2 35 [2] c6 2d [2] 81 2f [2] c6 3e [2] 88 32 [2] 84 38 [2] 93 33 [2] 88 7d [2] b5 }

  condition:
    any of them
}