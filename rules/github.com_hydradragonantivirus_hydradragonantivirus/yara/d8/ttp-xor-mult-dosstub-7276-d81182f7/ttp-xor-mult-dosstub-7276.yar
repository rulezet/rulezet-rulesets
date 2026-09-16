rule TTP_XOR_MULT_DOSStub_7276 {
  strings:
    $key_7276 = { 26 1e [2] 52 06 [2] 15 04 [2] 52 15 [2] 1c 19 [2] 10 13 [2] 07 18 [2] 1c 56 [2] 21 }

  condition:
    any of them
}