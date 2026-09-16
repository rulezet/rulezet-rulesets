rule TTP_XOR_MULT_DOSStub_e16d {
  strings:
    $key_e16d = { b5 05 [2] c1 1d [2] 86 1f [2] c1 0e [2] 8f 02 [2] 83 08 [2] 94 03 [2] 8f 4d [2] b2 }

  condition:
    any of them
}