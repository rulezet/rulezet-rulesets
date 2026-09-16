rule TTP_XOR_MULT_DOSStub_e15e {
  strings:
    $key_e15e = { b5 36 [2] c1 2e [2] 86 2c [2] c1 3d [2] 8f 31 [2] 83 3b [2] 94 30 [2] 8f 7e [2] b2 }

  condition:
    any of them
}