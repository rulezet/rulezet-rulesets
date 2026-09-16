rule TTP_XOR_MULT_DOSStub_34fa {
  strings:
    $key_34fa = { 60 92 [2] 14 8a [2] 53 88 [2] 14 99 [2] 5a 95 [2] 56 9f [2] 41 94 [2] 5a da [2] 67 }

  condition:
    any of them
}