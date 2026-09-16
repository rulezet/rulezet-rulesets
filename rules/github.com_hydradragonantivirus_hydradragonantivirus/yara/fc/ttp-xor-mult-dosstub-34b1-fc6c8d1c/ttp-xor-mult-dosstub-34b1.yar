rule TTP_XOR_MULT_DOSStub_34b1 {
  strings:
    $key_34b1 = { 60 d9 [2] 14 c1 [2] 53 c3 [2] 14 d2 [2] 5a de [2] 56 d4 [2] 41 df [2] 5a 91 [2] 67 }

  condition:
    any of them
}