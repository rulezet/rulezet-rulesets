rule TTP_XOR_MULT_DOSStub_34f5 {
  strings:
    $key_34f5 = { 60 9d [2] 14 85 [2] 53 87 [2] 14 96 [2] 5a 9a [2] 56 90 [2] 41 9b [2] 5a d5 [2] 67 }

  condition:
    any of them
}