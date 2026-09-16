rule TTP_XOR_MULT_DOSStub_6076 {
  strings:
    $key_6076 = { 34 1e [2] 40 06 [2] 07 04 [2] 40 15 [2] 0e 19 [2] 02 13 [2] 15 18 [2] 0e 56 [2] 33 }

  condition:
    any of them
}