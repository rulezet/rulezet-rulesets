rule TTP_XOR_MULT_DOSStub_b3ef {
  strings:
    $key_b3ef = { e7 87 [2] 93 9f [2] d4 9d [2] 93 8c [2] dd 80 [2] d1 8a [2] c6 81 [2] dd cf [2] e0 }

  condition:
    any of them
}