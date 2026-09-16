rule TTP_XOR_MULT_DOSStub_bbb6 {
  strings:
    $key_bbb6 = { ef de [2] 9b c6 [2] dc c4 [2] 9b d5 [2] d5 d9 [2] d9 d3 [2] ce d8 [2] d5 96 [2] e8 }

  condition:
    any of them
}