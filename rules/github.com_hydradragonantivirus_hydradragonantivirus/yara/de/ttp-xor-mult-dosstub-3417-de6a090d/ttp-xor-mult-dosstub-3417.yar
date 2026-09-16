rule TTP_XOR_MULT_DOSStub_3417 {
  strings:
    $key_3417 = { 60 7f [2] 14 67 [2] 53 65 [2] 14 74 [2] 5a 78 [2] 56 72 [2] 41 79 [2] 5a 37 [2] 67 }

  condition:
    any of them
}