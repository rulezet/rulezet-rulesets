rule TTP_XOR_MULT_DOSStub_34f6 {
  strings:
    $key_34f6 = { 60 9e [2] 14 86 [2] 53 84 [2] 14 95 [2] 5a 99 [2] 56 93 [2] 41 98 [2] 5a d6 [2] 67 }

  condition:
    any of them
}