rule TTP_XOR_MULT_DOSStub_3407 {
  strings:
    $key_3407 = { 60 6f [2] 14 77 [2] 53 75 [2] 14 64 [2] 5a 68 [2] 56 62 [2] 41 69 [2] 5a 27 [2] 67 }

  condition:
    any of them
}