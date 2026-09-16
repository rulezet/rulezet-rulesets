rule TTP_XOR_MULT_DOSStub_0fac {
  strings:
    $key_0fac = { 5b c4 [2] 2f dc [2] 68 de [2] 2f cf [2] 61 c3 [2] 6d c9 [2] 7a c2 [2] 61 8c [2] 5c }

  condition:
    any of them
}