rule TTP_XOR_MULT_DOSStub_8671 {
  strings:
    $key_8671 = { d2 19 [2] a6 01 [2] e1 03 [2] a6 12 [2] e8 1e [2] e4 14 [2] f3 1f [2] e8 51 [2] d5 }

  condition:
    any of them
}