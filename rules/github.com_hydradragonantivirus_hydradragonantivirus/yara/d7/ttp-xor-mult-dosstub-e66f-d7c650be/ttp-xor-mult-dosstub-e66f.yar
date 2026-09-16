rule TTP_XOR_MULT_DOSStub_e66f {
  strings:
    $key_e66f = { b2 07 [2] c6 1f [2] 81 1d [2] c6 0c [2] 88 00 [2] 84 0a [2] 93 01 [2] 88 4f [2] b5 }

  condition:
    any of them
}