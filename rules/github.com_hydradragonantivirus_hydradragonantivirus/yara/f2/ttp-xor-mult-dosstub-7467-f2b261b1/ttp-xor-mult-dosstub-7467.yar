rule TTP_XOR_MULT_DOSStub_7467 {
  strings:
    $key_7467 = { 20 0f [2] 54 17 [2] 13 15 [2] 54 04 [2] 1a 08 [2] 16 02 [2] 01 09 [2] 1a 47 [2] 27 }

  condition:
    any of them
}