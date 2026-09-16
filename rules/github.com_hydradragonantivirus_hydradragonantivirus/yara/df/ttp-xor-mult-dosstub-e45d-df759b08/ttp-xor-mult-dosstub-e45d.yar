rule TTP_XOR_MULT_DOSStub_e45d {
  strings:
    $key_e45d = { b0 35 [2] c4 2d [2] 83 2f [2] c4 3e [2] 8a 32 [2] 86 38 [2] 91 33 [2] 8a 7d [2] b7 }

  condition:
    any of them
}