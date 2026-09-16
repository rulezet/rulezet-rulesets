rule TTP_XOR_MULT_DOSStub_e16f {
  strings:
    $key_e16f = { b5 07 [2] c1 1f [2] 86 1d [2] c1 0c [2] 8f 00 [2] 83 0a [2] 94 01 [2] 8f 4f [2] b2 }

  condition:
    any of them
}