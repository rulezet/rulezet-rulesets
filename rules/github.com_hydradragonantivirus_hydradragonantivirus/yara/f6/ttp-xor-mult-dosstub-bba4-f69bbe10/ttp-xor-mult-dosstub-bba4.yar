rule TTP_XOR_MULT_DOSStub_bba4 {
  strings:
    $key_bba4 = { ef cc [2] 9b d4 [2] dc d6 [2] 9b c7 [2] d5 cb [2] d9 c1 [2] ce ca [2] d5 84 [2] e8 }

  condition:
    any of them
}