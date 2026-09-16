rule TTP_XOR_MULT_DOSStub_34e7 {
  strings:
    $key_34e7 = { 60 8f [2] 14 97 [2] 53 95 [2] 14 84 [2] 5a 88 [2] 56 82 [2] 41 89 [2] 5a c7 [2] 67 }

  condition:
    any of them
}