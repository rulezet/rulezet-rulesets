rule TTP_XOR_MULT_DOSStub_cba4 {
  strings:
    $key_cba4 = { 9f cc [2] eb d4 [2] ac d6 [2] eb c7 [2] a5 cb [2] a9 c1 [2] be ca [2] a5 84 [2] 98 }

  condition:
    any of them
}