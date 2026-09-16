rule TTP_XOR_MULT_DOSStub_caac {
  strings:
    $key_caac = { 9e c4 [2] ea dc [2] ad de [2] ea cf [2] a4 c3 [2] a8 c9 [2] bf c2 [2] a4 8c [2] 99 }

  condition:
    any of them
}