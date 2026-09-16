rule TTP_XOR_MULT_DOSStub_3467 {
  strings:
    $key_3467 = { 60 0f [2] 14 17 [2] 53 15 [2] 14 04 [2] 5a 08 [2] 56 02 [2] 41 09 [2] 5a 47 [2] 67 }

  condition:
    any of them
}