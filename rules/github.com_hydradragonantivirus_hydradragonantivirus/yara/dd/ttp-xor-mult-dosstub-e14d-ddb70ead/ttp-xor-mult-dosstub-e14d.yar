rule TTP_XOR_MULT_DOSStub_e14d {
  strings:
    $key_e14d = { b5 25 [2] c1 3d [2] 86 3f [2] c1 2e [2] 8f 22 [2] 83 28 [2] 94 23 [2] 8f 6d [2] b2 }

  condition:
    any of them
}