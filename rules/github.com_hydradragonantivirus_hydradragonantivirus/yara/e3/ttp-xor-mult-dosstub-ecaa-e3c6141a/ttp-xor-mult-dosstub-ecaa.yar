rule TTP_XOR_MULT_DOSStub_ecaa {
  strings:
    $key_ecaa = { b8 c2 [2] cc da [2] 8b d8 [2] cc c9 [2] 82 c5 [2] 8e cf [2] 99 c4 [2] 82 8a [2] bf }

  condition:
    any of them
}