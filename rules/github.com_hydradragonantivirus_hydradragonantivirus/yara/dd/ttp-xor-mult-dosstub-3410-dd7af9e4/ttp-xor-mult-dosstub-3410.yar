rule TTP_XOR_MULT_DOSStub_3410 {
  strings:
    $key_3410 = { 60 78 [2] 14 60 [2] 53 62 [2] 14 73 [2] 5a 7f [2] 56 75 [2] 41 7e [2] 5a 30 [2] 67 }

  condition:
    any of them
}