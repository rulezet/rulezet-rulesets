rule TTP_XOR_MULT_DOSStub_09aa {
  strings:
    $key_09aa = { 5d c2 [2] 29 da [2] 6e d8 [2] 29 c9 [2] 67 c5 [2] 6b cf [2] 7c c4 [2] 67 8a [2] 5a }

  condition:
    any of them
}