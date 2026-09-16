rule TTP_XOR_MULT_DOSStub_f16f {
  strings:
    $key_f16f = { a5 07 [2] d1 1f [2] 96 1d [2] d1 0c [2] 9f 00 [2] 93 0a [2] 84 01 [2] 9f 4f [2] a2 }

  condition:
    any of them
}