rule TTP_XOR_MULT_DOSStub_dda7 {
  strings:
    $key_dda7 = { 89 cf [2] fd d7 [2] ba d5 [2] fd c4 [2] b3 c8 [2] bf c2 [2] a8 c9 [2] b3 87 [2] 8e }

  condition:
    any of them
}