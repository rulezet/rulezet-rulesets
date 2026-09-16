rule TTP_XOR_MULT_DOSStub_b66f {
  strings:
    $key_b66f = { e2 07 [2] 96 1f [2] d1 1d [2] 96 0c [2] d8 00 [2] d4 0a [2] c3 01 [2] d8 4f [2] e5 }

  condition:
    any of them
}