rule TTP_XOR_MULT_DOSStub_0aac {
  strings:
    $key_0aac = { 5e c4 [2] 2a dc [2] 6d de [2] 2a cf [2] 64 c3 [2] 68 c9 [2] 7f c2 [2] 64 8c [2] 59 }

  condition:
    any of them
}